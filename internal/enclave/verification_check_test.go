package enclave

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestVerificationCheckSeesEveryVerification(t *testing.T) {
	var checked []string
	s, err := New(Config{Host: "enclave.example", Repo: "org/repo", VerificationCheck: func(v *verify.Verification) error {
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
		s, err := New(Config{Host: "enclave.example", Repo: "org/repo", VerificationCheck: func(*verify.Verification) error {
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
		var attestation *AttestationError
		require.ErrorAs(t, err, &attestation)
		require.ErrorContains(t, err, "verification check rejected enclave.example")
		require.Equal(t, 1, verifications, "a rejection is a decision about the evidence, so it isn't retried")
	})
}
