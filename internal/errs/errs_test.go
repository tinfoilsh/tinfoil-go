package errs

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPassCancellation(t *testing.T) {
	cause := errors.New("cause")
	live := context.Background()
	done, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, PassCancellation(done, nil))
	require.Equal(t, context.Canceled, PassCancellation(done, Network(cause)), "the caller's cancellation replaces a failure")
	require.Equal(t, context.Canceled, PassCancellation(done, cause))
	require.ErrorIs(t, PassCancellation(done, Configuration(cause)), ErrConfiguration, "no cancellation causes a configuration error")

	sdkTimeout := Network(context.DeadlineExceeded)
	require.Equal(t, sdkTimeout, PassCancellation(live, sdkTimeout), "a context error under a live caller context is the SDK's")
}
