package enclave

import (
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestVerificationCheckSeesEveryVerification(t *testing.T) {
	var checked []string
	s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(v *verify.Verification) error {
		checked = append(checked, v.CodeTag())
		*v = verify.Verification{} // the check gets a copy
		return nil
	}})
	require.NoError(t, err)
	s.fetch = func() (*verify.Verification, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	}
	verified, err := s.Verify()
	require.NoError(t, err)
	require.Equal(t, "key", verified.CodeTag())
	_, err = s.Verify()
	require.NoError(t, err)
	require.Equal(t, []string{"key", "key"}, checked, "every verification is checked")
}

func TestVerificationCheckRejectsWithoutRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rejection := errors.New("unapproved release")
		s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(*verify.Verification) error {
			return rejection
		}})
		require.NoError(t, err)
		var verifications int
		s.fetch = func() (*verify.Verification, error) {
			verifications++
			return testState(time.Now().Add(time.Hour), "key"), nil
		}
		_, err = s.Verify()
		require.ErrorIs(t, err, rejection)
		require.ErrorIs(t, err, errs.ErrAttestation)
		require.ErrorContains(t, err, "verification check rejected enclave.example")
		require.Equal(t, 1, verifications, "a rejection is a decision about the evidence, so it isn't retried")
	})
}

// A check's error is an attestation error, even when it is an SDK error of
// another category, which would otherwise make the result match two.
func TestVerificationCheckRejectionHasOneCategory(t *testing.T) {
	cause := errors.New("unapproved release")
	for _, returned := range []error{errs.Network(cause), errs.Configuration(cause), fmt.Errorf("check: %w", errs.Attestation(cause))} {
		t.Run(returned.Error(), func(t *testing.T) {
			s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(*verify.Verification) error {
				return returned
			}})
			require.NoError(t, err)
			var verifications int
			s.fetch = func() (*verify.Verification, error) {
				verifications++
				return testState(time.Now().Add(time.Hour), "key"), nil
			}
			_, err = s.Verify()
			testutil.RequireCategory(t, err, errs.ErrAttestation)
			require.ErrorIs(t, err, cause, "the check's error stays reachable")
			require.ErrorContains(t, err, returned.Error())
			var rejected *rejectedError
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, 1, verifications, "a rejection isn't retried, whatever it carries")
		})
	}
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
				s, err := New(Config{Host: "enclave.example", Pin: verify.Pin{Repo: "org/repo"}, VerificationCheck: func(*verify.Verification) error {
					checks++
					if checks <= tc.slowCalls {
						time.Sleep(2 * time.Minute) // outlasts the verification's deadline
					}
					return nil
				}})
				require.NoError(t, err)
				var fetches int
				s.fetch = func() (*verify.Verification, error) {
					fetches++
					return testState(time.Now().Add(time.Minute), "key"), nil
				}
				verified, err := s.Verify()
				require.Equal(t, 2, fetches, "an expiry after the check is retried with fresh evidence")
				if tc.slowCalls == 2 {
					require.ErrorIs(t, err, ErrFreshnessExpired)
					return
				}
				require.NoError(t, err)
				require.True(t, time.Now().Before(verified.FreshnessExpiresAt()), "Verify returns only fresh verifications")
			})
		})
	}
}
