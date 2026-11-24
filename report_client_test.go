package tinfoil

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

type recordedAttempt struct {
	host   string
	report *verify.VerificationReport
	err    error
}

// recordAttempts returns an OnVerificationAttempt callback and the attempts that it
// has seen.
func recordAttempts() (func(string, *verify.VerificationReport, error), func() []recordedAttempt) {
	var mu sync.Mutex
	var seen []recordedAttempt
	return func(host string, report *verify.VerificationReport, err error) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, recordedAttempt{host, report, err})
		}, func() []recordedAttempt {
			mu.Lock()
			defer mu.Unlock()
			return append([]recordedAttempt(nil), seen...)
		}
}

// The verifier's rejection reaches the caller as an attestation error from
// which the VerificationError and its report are reachable, and
// LastVerificationAttempt and OnVerificationAttempt give the same error.
func TestClientReportsARejectedDocument(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		onVerification, seen := recordAttempts()
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{
			OnVerificationAttempt: onVerification,
			FetchAttestation: AttestationFetcherFunc(func(context.Context, string, []byte) ([]byte, error) {
				return []byte(`{}`), nil
			}),
		})
		require.NoError(t, err)
		_, err = c.EnsureVerified(context.Background())
		testutil.RequireCategory(t, err, ErrAttestation)
		var rejected *verify.VerificationError
		require.ErrorAs(t, err, &rejected)
		require.Equal(t, verify.LayerEnvelope, rejected.Layer)
		failed, ok := rejected.Report.Failed()
		require.True(t, ok)
		require.Equal(t, verify.LayerEnvelope, failed.Layer)
		require.NotNil(t, rejected.Report.PartialFacts)
		require.Nil(t, rejected.Report.VerifiedFacts)

		last, lastErr := c.LastVerificationAttempt()
		require.Nil(t, last)
		require.Same(t, err, lastErr)
		attempts := seen()
		require.Len(t, attempts, 2, "the verification has one retry")
		for _, a := range attempts {
			require.Equal(t, "enclave.example", a.host)
			require.Nil(t, a.report)
			require.ErrorAs(t, a.err, &rejected)
		}
		require.Same(t, err, attempts[1].err)
	})
}

// A fetch that fails is a network error with no report.
func TestClientReportsAFailedFetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		onVerification, seen := recordAttempts()
		unreachable := errors.New("unreachable")
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{
			OnVerificationAttempt: onVerification,
			FetchAttestation: AttestationFetcherFunc(func(context.Context, string, []byte) ([]byte, error) {
				return nil, unreachable
			}),
		})
		require.NoError(t, err)
		_, err = c.EnsureVerified(context.Background())
		testutil.RequireCategory(t, err, ErrNetwork)
		require.NotErrorAs(t, err, new(*verify.VerificationError))
		last, lastErr := c.LastVerificationAttempt()
		require.Nil(t, last)
		require.Same(t, err, lastErr)
		attempts := seen()
		require.Len(t, attempts, 2)
		require.Same(t, err, attempts[1].err)
	})
}
