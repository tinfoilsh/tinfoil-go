package tinfoil

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// requireReportHost requires report to name host, in its metadata and in its
// JSON form.
func requireReportHost(t *testing.T, host string, report *verify.VerificationReport) {
	t.Helper()
	require.NotNil(t, report)
	require.Equal(t, host, report.Metadata.Host)
	encoded, err := json.Marshal(report)
	require.NoError(t, err)
	var decoded struct {
		Metadata map[string]any `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, host, decoded.Metadata["host"], "%s", encoded)
}

type recordedAttempt struct {
	host   string
	report *verify.VerificationReport
	err    error
}

// recordAttempts returns an OnVerification callback and the attempts that it
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
// LastVerification and OnVerification give the same error.
func TestClientReportsARejectedDocument(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		onVerification, seen := recordAttempts()
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{
			OnVerification: onVerification,
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
		requireReportHost(t, "enclave.example", rejected.Report)

		last, lastErr := c.LastVerification()
		require.Nil(t, last)
		require.Same(t, err, lastErr)
		attempts := seen()
		require.Len(t, attempts, 2, "the verification has one retry")
		for _, a := range attempts {
			require.Equal(t, "enclave.example", a.host)
			require.Nil(t, a.report)
			require.ErrorAs(t, a.err, &rejected)
			requireReportHost(t, "enclave.example", rejected.Report)
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
			OnVerification: onVerification,
			FetchAttestation: AttestationFetcherFunc(func(context.Context, string, []byte) ([]byte, error) {
				return nil, unreachable
			}),
		})
		require.NoError(t, err)
		_, err = c.EnsureVerified(context.Background())
		testutil.RequireCategory(t, err, ErrNetwork)
		require.NotErrorAs(t, err, new(*verify.VerificationError))
		last, lastErr := c.LastVerification()
		require.Nil(t, last)
		require.Same(t, err, lastErr)
		attempts := seen()
		require.Len(t, attempts, 2)
		require.Same(t, err, attempts[1].err)
	})
}

// Every report that a client hands out names the host that it verified,
// since the verifier doesn't know it.
func TestClientReportsNameTheHost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		onVerification, seen := recordAttempts()
		e := enclave.NewForTest("enclave.example:8443", func() (*verify.VerificationReport, error) {
			report := verifytest.NewReport(verifytest.Fields{FreshnessExpiresAt: time.Now().Add(time.Hour), CryptoMaterial: []document.CryptoMaterialItem{
				{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: "aa"},
				{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: strings.Repeat("11", 32)},
			}})
			require.Empty(t, report.Metadata.Host, "the verifier names no host")
			return report, nil
		}, onVerification)
		c, err := newAttestedClient(transport.WithEHBP(nil, e), "", "")
		require.NoError(t, err)

		ensured, err := c.EnsureVerified(t.Context())
		require.NoError(t, err)
		requireReportHost(t, "enclave.example:8443", ensured)
		reverified, err := c.Reverify(t.Context())
		require.NoError(t, err)
		requireReportHost(t, "enclave.example:8443", reverified)
		last, err := c.LastVerification()
		require.NoError(t, err)
		requireReportHost(t, "enclave.example:8443", last)
		attempts := seen()
		require.Len(t, attempts, 2)
		for _, a := range attempts {
			requireReportHost(t, "enclave.example:8443", a.report)
		}
	})
}
