package errs

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterrupted(t *testing.T) {
	cause := errors.New("cause")
	live := context.Background()
	done, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, Interrupted(done, nil))
	interrupted := fmt.Errorf("Get: %w", context.Canceled)
	require.Equal(t, interrupted, Interrupted(done, interrupted), "the call's own error, as it is")
	joined := Interrupted(done, cause)
	require.ErrorIs(t, joined, context.Canceled, "a cause that doesn't name the cancellation is joined with it")
	require.ErrorIs(t, joined, cause)
	require.NotErrorIs(t, joined, ErrNetwork)

	err := Interrupted(live, cause)
	require.ErrorIs(t, err, ErrNetwork)
	require.ErrorIs(t, err, cause)

	sdkTimeout := Interrupted(live, context.DeadlineExceeded)
	require.ErrorIs(t, sdkTimeout, ErrNetwork, "a context error under a live caller context is the SDK's")

	attestation := Attestation(cause)
	require.Equal(t, attestation, Interrupted(live, attestation), "an SDK error keeps its category")
}
