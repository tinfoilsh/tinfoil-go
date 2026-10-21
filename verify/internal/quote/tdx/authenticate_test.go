package tdx

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The embedded Intel SGX root is parsed on first use rather than in an init()
// that panicked, so nothing fails loudly at startup if the committed PEM is
// bad. Assert here that it parses.
func TestEmbeddedIntelRootParses(t *testing.T) {
	pool, err := embeddedIntelRoots()
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestAuthenticateRequiresVerificationTime(t *testing.T) {
	_, err := Authenticate(Evidence{}, time.Time{}, nil)
	require.ErrorContains(t, err, "verification time is required", "the library would substitute its own clock")
}
