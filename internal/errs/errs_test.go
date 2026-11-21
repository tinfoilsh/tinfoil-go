package errs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// requireCategory fails unless err is in category and in no other one; a nil
// category requires that err is in none.
func requireCategory(t *testing.T, err, category error) {
	t.Helper()
	for _, c := range categories {
		require.Equal(t, c == category, errors.Is(err, c), "errors.Is(err, %v); err: %v", c, err)
	}
}

func TestFinish(t *testing.T) {
	cause := errors.New("cause")
	live := context.Background()
	done, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Time{})
	defer cancelExpired()

	for name, tc := range map[string]struct {
		ctx      context.Context
		err      error
		category error
		same     bool
	}{
		"a plain error":                                     {live, cause, ErrNetwork, false},
		"a plain error before the cancellation":             {done, cause, ErrNetwork, false},
		"the SDK's timeout under a live caller":             {live, fmt.Errorf("Get: %w", context.DeadlineExceeded), ErrNetwork, false},
		"the SDK's timeout, then the caller's cancellation": {done, &url.Error{Op: "Get", URL: "https://x", Err: context.DeadlineExceeded}, ErrNetwork, false},
		"the caller's cancellation":                         {done, &url.Error{Op: "Get", URL: "https://x", Err: context.Canceled}, nil, true},
		"the caller's deadline":                             {expired, fmt.Errorf("verifying: %w", context.DeadlineExceeded), nil, true},
		"an attestation error":                              {live, Attestation(cause), ErrAttestation, true},
		"a configuration error under a cancellation":        {done, fmt.Errorf("context: %w", Configuration(cause)), ErrConfiguration, true},
		"a network error that wraps the cancellation":       {done, Network(context.Canceled), ErrNetwork, true},
		"a bare category":                                   {live, fmt.Errorf("x: %w", ErrAttestation), ErrAttestation, true},
	} {
		t.Run(name, func(t *testing.T) {
			got := Finish(tc.ctx, tc.err)
			requireCategory(t, got, tc.category)
			require.ErrorIs(t, got, tc.err, "the error stays reachable")
			if tc.same {
				require.Same(t, tc.err, got, "returned as it is")
			}
			require.Same(t, got, Finish(tc.ctx, got), "applying Finish twice changes nothing")
		})
	}
	require.NoError(t, Finish(live, nil))
	require.NoError(t, Finish(done, nil))
}

func TestWrapKeepsACategory(t *testing.T) {
	cause := errors.New("cause")
	for _, wrap := range []func(error) error{WrapNetwork, WrapAttestation} {
		require.NoError(t, wrap(nil))
		for _, classified := range []error{Configuration(cause), fmt.Errorf("context: %w", Network(cause)), errors.Join(Attestation(cause), context.Canceled)} {
			require.Same(t, classified, wrap(classified))
		}
	}
	requireCategory(t, WrapNetwork(cause), ErrNetwork)
	requireCategory(t, WrapAttestation(cause), ErrAttestation)
}

// customIs matches target by a method of its own, as fs.ErrNotExist-style
// errors do.
type customIs struct{ msg string }

func (e *customIs) Error() string        { return e.msg }
func (e *customIs) Is(target error) bool { return target == fs.ErrNotExist }

func TestUncategorized(t *testing.T) {
	require.NoError(t, Uncategorized(nil))
	plain := fmt.Errorf("callback: %w", context.Canceled)
	require.Same(t, plain, Uncategorized(plain), "an error without a category is returned as it is")

	cause := &url.Error{Op: "Get", URL: "https://x", Err: &customIs{"refused"}}
	for name, err := range map[string]error{
		"an SDK error":                 Network(cause),
		"a wrapped SDK error":          fmt.Errorf("callback: %w", Attestation(cause)),
		"a nested SDK error":           Configuration(fmt.Errorf("inner: %w", Network(cause))),
		"a joined SDK error":           errors.Join(errors.New("other"), Attestation(cause)),
		"a category":                   fmt.Errorf("callback: %w: %w", ErrNetwork, cause),
		"a category on its own branch": errors.Join(ErrAttestation, cause),
	} {
		t.Run(name, func(t *testing.T) {
			got := Uncategorized(err)
			require.Equal(t, err.Error(), got.Error(), "the message is kept")
			requireCategory(t, got, nil)
			var sdkError *Error
			require.False(t, errors.As(got, &sdkError), "no SDK error is reachable")
			require.ErrorIs(t, got, cause, "the cause is reachable")
			var urlErr *url.Error
			require.ErrorAs(t, got, &urlErr)
			require.Same(t, cause, urlErr)
			require.ErrorIs(t, got, fs.ErrNotExist, "an Is method in the chain still applies")
			requireCategory(t, Attestation(got), ErrAttestation)
		})
	}

	sentinel := Uncategorized(ErrNetwork)
	require.Equal(t, ErrNetwork.Error(), sentinel.Error())
	requireCategory(t, sentinel, nil)
}
