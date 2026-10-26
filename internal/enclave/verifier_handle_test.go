package enclave

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestEnsureVerifiedReusesValidVerification(t *testing.T) {
	s, err := NewHandle(Config{Host: "enclave.example", Repo: "org/repo"})
	require.NoError(t, err)
	var verifications int
	s.verify = func() (*verify.Verification, error) {
		verifications++
		return testState(time.Now().Add(time.Hour), "key"), nil
	}
	for range 2 {
		_, err := s.EnsureVerified(context.Background())
		require.NoError(t, err)
	}
	require.Equal(t, 1, verifications, "a valid verification is reused")

	_, err = s.Reverify(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, verifications, "Reverify always verifies")
}
