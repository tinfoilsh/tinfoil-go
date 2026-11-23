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

func TestUncategorized(t *testing.T) {
	cause := errors.New("cause")
	require.Same(t, cause, Uncategorized(cause), "an error without a category, as it is")
	require.NoError(t, Uncategorized(nil))

	callback := fmt.Errorf("callback: %w", Network(Configuration(cause)))
	err := Uncategorized(callback)
	require.Equal(t, callback.Error(), err.Error())
	require.ErrorIs(t, err, cause)
	for _, category := range []error{ErrConfiguration, ErrNetwork, ErrAttestation} {
		require.NotErrorIs(t, err, category)
	}

	sentinel := fmt.Errorf("callback: %w", ErrNetwork)
	err = Uncategorized(sentinel)
	require.Equal(t, sentinel.Error(), err.Error())
	require.NotErrorIs(t, err, ErrNetwork, "a category that the error wraps without an SDK error")
}
