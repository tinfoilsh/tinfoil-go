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
	require.Same(t, interrupted, Interrupted(done, interrupted), "the call's own error, as it is")
	failedFirst := Interrupted(done, cause)
	require.ErrorIs(t, failedFirst, ErrNetwork, "a failure that came before the cancellation keeps its category")
	require.ErrorIs(t, failedFirst, cause)
	sdkTimeoutThenCancel := Interrupted(done, fmt.Errorf("Get: %w", context.DeadlineExceeded))
	require.ErrorIs(t, sdkTimeoutThenCancel, ErrNetwork, "the SDK's timeout, though the caller cancelled afterwards")

	err := Interrupted(live, cause)
	require.ErrorIs(t, err, ErrNetwork)
	require.ErrorIs(t, err, cause)

	sdkTimeout := Interrupted(live, context.DeadlineExceeded)
	require.ErrorIs(t, sdkTimeout, ErrNetwork, "a context error under a live caller context is the SDK's")

	attestation := Attestation(cause)
	require.Equal(t, attestation, Interrupted(live, attestation), "an SDK error keeps its category")
}
