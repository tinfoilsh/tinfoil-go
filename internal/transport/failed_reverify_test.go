package transport

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// keyedServer is a test mode whose round trippers record the key that each
// request is sent under and count the closes of their idle connections.
type keyedServer struct {
	sent   []string
	closes map[string]int
}

func newKeyedServer() *keyedServer {
	return &keyedServer{closes: map[string]int{}}
}

func (k *keyedServer) mode() mode {
	return testMode(func(v *verify.Verification) (http.RoundTripper, error) {
		key := v.CodeTag()
		return &closeRecorder{
			RoundTripper: roundTripFunc(func(*http.Request) (*http.Response, error) {
				k.sent = append(k.sent, key)
				return testResponse(), nil
			}),
			close: func() { k.closes[key]++ },
		}, nil
	})
}

type closeRecorder struct {
	http.RoundTripper
	close func()
}

func (c *closeRecorder) CloseIdleConnections() { c.close() }

// verifications returns a fetch that returns each result in turn and repeats
// the last one.
func verifications(results ...func() (*verify.Verification, error)) (func() (*verify.Verification, error), *int) {
	var calls int
	return func() (*verify.Verification, error) {
		result := results[min(calls, len(results)-1)]
		calls++
		return result()
	}, &calls
}

func fresh(key string) func() (*verify.Verification, error) {
	return func() (*verify.Verification, error) { return testState(time.Now().Add(time.Hour), key), nil }
}

func failing(err error) func() (*verify.Verification, error) {
	return func() (*verify.Verification, error) { return nil, err }
}

var errBadDocument = errs.Attestation(errors.New("the document fails verification"))

func send(t *testing.T, tr http.RoundTripper) error {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
	resp, err := tr.RoundTrip(req)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestFailedReverifyDiscardsVerification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newKeyedServer()
		// Verify retries once, so the re-verification fails twice.
		fetch, calls := verifications(fresh("old"), failing(errBadDocument), failing(errBadDocument), fresh("new"))
		transport := newTestTransport(t, nil, fetch, server.mode())
		require.NoError(t, send(t, transport))

		_, err := transport.Reverify(context.Background())
		require.ErrorIs(t, err, errs.ErrAttestation)
		require.False(t, currentValid(transport), "the verification is discarded")
		require.Equal(t, 1, server.closes["old"], "its idle connections are closed")

		require.NoError(t, send(t, transport))
		require.Equal(t, 4, *calls, "the next request verifies again")
		require.Equal(t, []string{"old", "new"}, server.sent, "the next request goes out under the new keys")
	})
}

func TestFailedReverifyFailsLaterRequestsWhileAttestationFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newKeyedServer()
		fetch, calls := verifications(fresh("old"), failing(errBadDocument))
		transport := newTestTransport(t, nil, fetch, server.mode())
		require.NoError(t, send(t, transport))

		_, err := transport.Reverify(context.Background())
		require.ErrorIs(t, err, errs.ErrAttestation)

		require.ErrorIs(t, send(t, transport), errs.ErrAttestation)
		require.Equal(t, 5, *calls, "the next request verifies again, with one retry")
		require.Equal(t, []string{"old"}, server.sent, "nothing is sent after the failure")
	})
}

func TestFailedReverifyKeepsVerificationOnOtherFailures(t *testing.T) {
	for name, err := range map[string]error{
		"network":       errs.Network(errors.New("attestation source unavailable")),
		"configuration": errs.Configuration(errors.New("invalid attestation target")),
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				server := newKeyedServer()
				fetch, calls := verifications(fresh("old"), failing(err))
				transport := newTestTransport(t, nil, fetch, server.mode())
				require.NoError(t, send(t, transport))

				_, reverifyErr := transport.Reverify(context.Background())
				require.ErrorIs(t, reverifyErr, err)
				require.True(t, currentValid(transport), "a fresh verification survives the failure")
				before := *calls

				require.NoError(t, send(t, transport))
				require.Equal(t, before, *calls, "the next request needs no new verification")
				require.Equal(t, []string{"old", "old"}, server.sent)
				require.Zero(t, server.closes["old"])
			})
		})
	}
}

func TestCancelledReverifyKeepsVerification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		fetch, _ := verifications(fresh("old"), func() (*verify.Verification, error) {
			<-release
			return nil, errs.Network(errors.New("attestation source unavailable"))
		})
		transport := newTestTransport(t, nil, fetch, sendOK)
		require.NoError(t, send(t, transport))

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := transport.Reverify(ctx); done <- err }()
		synctest.Wait()
		cancel()
		require.ErrorIs(t, <-done, context.Canceled)
		require.True(t, currentValid(transport), "the caller's cancellation keeps the verification")
		require.NoError(t, send(t, transport))
		close(release)
		synctest.Wait()
		time.Sleep(2 * time.Second)
		require.True(t, currentValid(transport))
	})
}

// A key rejection invalidates the verification. When the verification that
// recovery runs fails attestation, the replay is not sent, and the rejected
// keys' idle connections are closed.
func TestFailedRecoveryAfterKeyRejectionSendsNothing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var sent int
		var closes int
		fetch, calls := verifications(fresh("old"), failing(errBadDocument))
		transport := newTestTransport(t, nil, fetch, testMode(func(*verify.Verification) (http.RoundTripper, error) {
			return &closeRecorder{
				RoundTripper: roundTripFunc(func(*http.Request) (*http.Response, error) {
					sent++
					return nil, &peerLacksKeyError{errCertMismatch}
				}),
				close: func() { closes++ },
			}, nil
		}))
		err := send(t, WithReplay(transport, IsKeyRejection))
		require.ErrorIs(t, err, errs.ErrAttestation)
		require.Equal(t, 1, sent, "the replay is not sent under the rejected keys")
		require.Equal(t, 3, *calls, "the first verification, then recovery with one retry")
		require.Equal(t, 1, closes, "the rejected keys' idle connections are closed")
		require.False(t, currentValid(transport))
	})
}

// A refresh after expiry that fails attestation leaves nothing usable, and the
// expired keys' idle connections are closed.
func TestFailedRefreshAfterExpiryClosesExpiredConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newKeyedServer()
		fetch, _ := verifications(func() (*verify.Verification, error) {
			return testState(time.Now().Add(time.Minute), "old"), nil
		}, failing(errBadDocument))
		transport := newTestTransport(t, nil, fetch, server.mode())
		require.NoError(t, send(t, transport))
		time.Sleep(2 * time.Minute)

		require.ErrorIs(t, send(t, transport), errs.ErrAttestation)
		require.Equal(t, []string{"old"}, server.sent)
		require.Equal(t, 1, server.closes["old"])
	})
}
