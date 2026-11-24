package enclave

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestVerificationCheckSeesEveryVerification(t *testing.T) {
	var checked []string
	s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(v *verify.VerifiedFacts) error {
		checked = append(checked, v.CodeTag())
		*v = verify.VerifiedFacts{} // the check gets a copy
		return nil
	}})
	require.NoError(t, err)
	s.fetch = func() (*verify.VerificationReport, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	}
	verified, err := s.Verify(nil)
	require.NoError(t, err)
	require.Equal(t, "key", verified.VerifiedFacts.CodeTag())
	_, err = s.Verify(nil)
	require.NoError(t, err)
	require.Equal(t, []string{"key", "key"}, checked, "every verification is checked")
}

func TestVerificationCheckRejectsWithoutRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rejection := errors.New("unapproved release")
		s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(*verify.VerifiedFacts) error {
			return rejection
		}})
		require.NoError(t, err)
		var verifications int
		s.fetch = func() (*verify.VerificationReport, error) {
			verifications++
			return testState(time.Now().Add(time.Hour), "key"), nil
		}
		_, err = s.Verify(nil)
		require.ErrorIs(t, err, rejection)
		require.ErrorIs(t, err, errs.ErrAttestation)
		require.ErrorContains(t, err, "verification check rejected enclave.example")
		require.Equal(t, 1, verifications, "a rejection is a decision about the evidence, so it isn't retried")
	})
}

func TestVerificationCheckRejectionIsOnlyAnAttestationError(t *testing.T) {
	cause := errors.New("release lookup failed")
	s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(*verify.VerifiedFacts) error {
		return errs.Network(cause)
	}})
	require.NoError(t, err)
	s.fetch = func() (*verify.VerificationReport, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	}
	_, err = s.Verify(nil)
	testutil.RequireCategory(t, err, errs.ErrAttestation)
	require.ErrorIs(t, err, cause)
}

func TestSlowVerificationCheckFetchesFreshEvidence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		slowCalls int
	}{
		{"retry succeeds", 1},
		{"every attempt expires", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var checks int
				s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(*verify.VerifiedFacts) error {
					checks++
					if checks <= tc.slowCalls {
						time.Sleep(2 * time.Minute) // outlasts the verification's deadline
					}
					return nil
				}})
				require.NoError(t, err)
				var fetches int
				s.fetch = func() (*verify.VerificationReport, error) {
					fetches++
					return testState(time.Now().Add(time.Minute), "key"), nil
				}
				verified, err := s.Verify(nil)
				require.Equal(t, 2, fetches, "an expiry after the check is retried with fresh evidence")
				if tc.slowCalls == 2 {
					require.ErrorIs(t, err, ErrFreshnessExpired)
					return
				}
				require.NoError(t, err)
				require.True(t, time.Now().Before(verified.VerifiedFacts.FreshnessExpiresAt()), "Verify returns only fresh verifications")
			})
		})
	}
}

// A check decides about trust, so it sees only verified facts, and never
// runs for a verification that the verifier rejected.
func TestVerificationCheckSkipsRejectedVerifications(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var checks int
		s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(*verify.VerifiedFacts) error {
			checks++
			return nil
		}})
		require.NoError(t, err)
		rejected := errs.Attestation(verifytest.Rejected("report signature is invalid"))
		s.fetch = func() (*verify.VerificationReport, error) { return nil, rejected }
		var retried []error
		_, err = s.Verify(func(err error) { retried = append(retried, err) })
		require.ErrorIs(t, err, errs.ErrAttestation)
		require.Zero(t, checks)
		require.Equal(t, []error{rejected}, retried, "the retried attempt is passed on before the retry")
	})
}
