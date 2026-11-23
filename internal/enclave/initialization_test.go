package enclave

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestRetriedVerificationReportsOnlyTheFinalCategory(t *testing.T) {
	firstCause, lastCause := errors.New("first attempt"), &rejectedError{host: "enclave.example", err: errors.New("last attempt")}
	for _, tc := range []struct {
		name        string
		first, last error
		category    error
	}{
		{"network then attestation", errs.Network(firstCause), errs.Attestation(lastCause), errs.ErrAttestation},
		{"attestation then network", errs.Attestation(firstCause), errs.Network(lastCause), errs.ErrNetwork},
		{"attestation then configuration", errs.Attestation(firstCause), errs.Configuration(lastCause), errs.ErrConfiguration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var attempts int
				s := NewForTest("enclave.example", func() (*verify.VerificationReport, error) {
					attempts++
					if attempts == 1 {
						return nil, tc.first
					}
					return nil, tc.last
				}, nil)
				_, err := s.Verify(nil)
				require.Equal(t, 2, attempts)
				testutil.RequireCategory(t, err, tc.category)
				var rejected *rejectedError
				require.ErrorAs(t, err, &rejected)
				require.Same(t, lastCause, rejected)
				require.NotErrorIs(t, err, firstCause)
				require.ErrorContains(t, err, tc.last.Error())
				require.ErrorContains(t, err, "first attempt: "+tc.first.Error())
			})
		})
	}
}

func TestInitializationRecovery(t *testing.T) {
	firstCause, lastCause := errors.New("first attempt"), errors.New("last attempt")
	for _, tc := range []struct {
		name        string
		first, last error
		attempts    int
	}{
		{"fetch then success", errs.Network(firstCause), nil, 2},
		{"attestation then success", errs.Attestation(firstCause), nil, 2},
		{"both attempts fail", errs.Network(firstCause), errs.Attestation(lastCause), 2},
		{"configuration", errs.Configuration(firstCause), nil, 1},
		{"native error", firstCause, nil, 1},
		{"configuration among causes", errors.Join(errs.Network(lastCause), errs.Configuration(firstCause)), nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := &Enclave{}
				var attempts int
				s.fetch = func() (*verify.VerificationReport, error) {
					attempts++
					if attempts == 1 {
						return testState(time.Now().Add(time.Hour), "rejected"), tc.first
					}
					return testState(time.Now().Add(time.Hour), "fresh"), tc.last
				}
				start := time.Now()
				verified, err := s.Verify(nil)
				require.Equal(t, tc.attempts, attempts)
				require.Equal(t, time.Duration(attempts-1)*time.Second, time.Since(start))
				if attempts == 2 && tc.last == nil {
					require.NoError(t, err)
					require.Equal(t, "fresh", verified.VerifiedFacts.CodeTag())
				} else if tc.last != nil {
					// Only the final attempt's error, as net/http.Transport
					// reports; the first is in the message alone.
					require.Same(t, tc.last, errors.Unwrap(err))
					require.NotErrorIs(t, err, firstCause)
					require.ErrorContains(t, err, firstCause.Error())
					require.Nil(t, verified)
				} else {
					require.Same(t, tc.first, err)
					require.Nil(t, verified)
				}
			})
		})
	}
}
