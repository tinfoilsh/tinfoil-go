package tinfoil

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// hangEveryFetch makes every fetch through the default HTTP client and
// transport wait until its request's context ends.
func hangEveryFetch(t *testing.T) {
	t.Helper()
	client, transport := http.DefaultClient, http.DefaultTransport
	t.Cleanup(func() { http.DefaultClient, http.DefaultTransport = client, transport })
	hang := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	http.DefaultClient = &http.Client{}
	http.DefaultTransport = hang
}

// requireNoCategory fails unless err is want itself, in no SDK category.
func requireNoCategory(t *testing.T, want, err error) {
	t.Helper()
	require.Equal(t, want, err, "the caller's context error, unchanged")
	for _, category := range []error{ErrNetwork, ErrAttestation, ErrConfiguration} {
		require.NotErrorIs(t, err, category)
	}
}

// The public fetch helpers, each with the limit that it imposes itself.
var fetchHelpers = map[string]struct {
	fetch func(ctx context.Context) error
	limit time.Duration
}{
	"AttestationRelay": {func(ctx context.Context) error {
		_, err := AttestationRelay{URL: "https://relay.example"}.FetchAttestation(ctx, "enclave.example", make([]byte, document.NonceSize))
		return err
	}, 30 * time.Second},
	"RouterListRelay": {func(ctx context.Context) error {
		_, err := RouterListRelay{URL: "https://relay.example"}.FetchRouterList(ctx)
		return err
	}, 30 * time.Second},
	"FetchCatalog": {func(ctx context.Context) error {
		_, err := FetchCatalog(ctx, "gateway.example")
		return err
	}, 10 * time.Second},
}

func TestFetchHelpersReturnTheCallersCancellation(t *testing.T) {
	hangEveryFetch(t)
	for name, helper := range fetchHelpers {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				requireNoCategory(t, context.Canceled, helper.fetch(ctx))

				ctx, cancel = context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- helper.fetch(ctx) }()
				synctest.Wait()
				cancel()
				requireNoCategory(t, context.Canceled, <-done)

				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				start := time.Now()
				err := helper.fetch(ctx)
				require.Equal(t, time.Second, time.Since(start))
				requireNoCategory(t, context.DeadlineExceeded, err)
			})
		})
	}
}

func TestFetchHelpersReportTheirOwnTimeoutAsANetworkError(t *testing.T) {
	hangEveryFetch(t)
	for name, helper := range fetchHelpers {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				err := helper.fetch(context.Background())
				require.Equal(t, helper.limit, time.Since(start))
				require.ErrorIs(t, err, ErrNetwork, "the SDK's limit, not the caller's cancellation")
			})
		})
	}
}

// A response that arrives before the caller cancels is the server's answer,
// not an interruption, so an error status stays a network error.
func TestAnErrorStatusIsNotACancellation(t *testing.T) {
	client, transport := http.DefaultClient, http.DefaultTransport
	t.Cleanup(func() { http.DefaultClient, http.DefaultTransport = client, transport })
	var cancel context.CancelFunc
	http.DefaultClient = &http.Client{}
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Body: http.NoBody}, nil
	})
	for name, helper := range fetchHelpers {
		t.Run(name, func(t *testing.T) {
			var ctx context.Context
			ctx, cancel = context.WithCancel(context.Background())
			err := helper.fetch(ctx)
			require.Error(t, ctx.Err(), "the caller cancelled after the response arrived")
			require.ErrorIs(t, err, ErrNetwork)
			require.NotErrorIs(t, err, context.Canceled)
		})
	}
}

// A client verifies under a context of its own, which serves every waiting
// caller, so its end is the SDK's timeout, whichever fetcher sees it.
func TestTheVerificationTimeoutIsANetworkError(t *testing.T) {
	hangEveryFetch(t)
	waitForTheEnd := AttestationFetcherFunc(func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	for name, fetcher := range map[string]AttestationFetcher{
		"AttestationRelay":       AttestationRelay{URL: "https://relay.example"},
		"AttestationFetcherFunc": waitForTheEnd,
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				_, err := NewEnclaveHTTPClient(context.Background(), "enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: fetcher})
				require.ErrorIs(t, err, ErrNetwork)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.Equal(t, 61*time.Second, time.Since(start), "two attempts of 30 seconds and the retry delay")

				var listErr error
				_, err = NewRouterHTTPClient(context.Background(), &RouterOptions{
					FetchAttestation: fetcher,
					FetchRouterList: RouterListFetcherFunc(func(ctx context.Context) ([]string, error) {
						<-ctx.Done()
						listErr = ctx.Err()
						return nil, listErr
					}),
				})
				require.Equal(t, context.DeadlineExceeded, listErr)
				require.ErrorIs(t, err, ErrNetwork, "discovery's timeout counts as an empty list, and the fallback's as a network error")
			})
		})
	}
}

func TestARouterListRelayTimeoutFallsBack(t *testing.T) {
	hangEveryFetch(t)
	synctest.Test(t, func(t *testing.T) {
		var hosts []string
		_, err := NewRouterHTTPClient(context.Background(), &RouterOptions{
			FetchAttestation: AttestationFetcherFunc(func(_ context.Context, host string, _ []byte) ([]byte, error) {
				hosts = append(hosts, host)
				return nil, errors.New("unreachable")
			}),
			FetchRouterList: RouterListRelay{URL: "https://relay.example"},
		})
		require.ErrorIs(t, err, ErrNetwork)
		require.Equal(t, []string{"inference.tinfoil.sh", "inference.tinfoil.sh"}, hosts, "the list's timeout counts as an empty list")
	})
}
