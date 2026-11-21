package errs

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterrupted(t *testing.T) {
	cause := errors.New("cause")
	live := context.Background()
	done, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, Interrupted(done, nil))
	require.Equal(t, context.Canceled, Interrupted(done, cause), "the caller's cancellation replaces the failure")

	err := Interrupted(live, cause)
	require.ErrorIs(t, err, ErrNetwork)
	require.ErrorIs(t, err, cause)

	sdkTimeout := Interrupted(live, context.DeadlineExceeded)
	require.ErrorIs(t, sdkTimeout, ErrNetwork, "a context error under a live caller context is the SDK's")

	attestation := Attestation(cause)
	require.Equal(t, attestation, Interrupted(live, attestation), "an SDK error keeps its category")
}
