package enclave

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestBoundTransportDiscardsSnapshotRefreshedDuringBuild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Handle{state: testEnclaveState(time.Now().Add(time.Hour), "old"), verify: func() (*verify.Verification, error) {
			return testState(time.Now().Add(time.Hour), "new"), nil
		}}
		release := make(chan struct{})
		var built, sent []string
		transport, err := bindTransport(s, func(verified *verify.Verification) (http.RoundTripper, error) {
			built = append(built, verified.CodeTag())
			if verified.CodeTag() == "old" {
				<-release
			}
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				sent = append(sent, verified.CodeTag())
				return testResponse(), nil
			}), nil
		}, nil)
		require.NoError(t, err)
		finished := make(chan error, 1)
		go func() {
			_, err := transport.EnsureVerified(context.Background())
			finished <- err
		}()
		synctest.Wait()
		_, err = verifyNow(s)
		require.NoError(t, err)
		close(release)
		require.NoError(t, <-finished)
		require.Equal(t, []string{"old"}, built, "a refresh builds nothing")
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		_, err = transport.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, []string{"old", "new"}, built, "the next request rebuilds for the new state")
		require.Equal(t, []string{"new"}, sent)
	})
}

func TestPlaintextRequestDoesNotRefresh(t *testing.T) {
	s := &Handle{state: testEnclaveState(time.Now().Add(time.Hour), "key"), verify: func() (*verify.Verification, error) {
		t.Error("re-verification cannot make a plaintext URL acceptable")
		return nil, errNoTLS
	}}
	_, err := tlsClient(t, s).Get("http://enclave.example")
	require.ErrorIs(t, err, errNoTLS)
}

func TestBindingsFailIndependently(t *testing.T) {
	var verifications int
	s := &Handle{verify: func() (*verify.Verification, error) {
		verifications++
		return testState(time.Now().Add(time.Hour), "key"), nil
	}}
	buildErr := errors.New("the verification endorses no key for this binding")
	failing, err := bindTransport(s, func(*verify.Verification) (http.RoundTripper, error) { return nil, buildErr }, nil)
	require.NoError(t, err)
	working, err := bindTransport(s, func(*verify.Verification) (http.RoundTripper, error) {
		return roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil }), nil
	}, nil)
	require.NoError(t, err)
	_, err = failing.EnsureVerified(context.Background())
	require.ErrorIs(t, err, buildErr)
	req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
	_, err = failing.RoundTrip(req)
	require.ErrorIs(t, err, buildErr)
	_, err = working.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, "key", current(s).CodeTag())
	require.Equal(t, 1, verifications, "a binding failure leaves the shared verification valid")
}

func TestBoundTransportRejectsSupersededState(t *testing.T) {
	s := &Handle{verify: func() (*verify.Verification, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	}}
	var built int
	transport, err := bindTransport(s, func(*verify.Verification) (http.RoundTripper, error) {
		built++
		return roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil }), nil
	}, nil)
	require.NoError(t, err)
	old, err := transport.EnsureVerified(context.Background())
	require.NoError(t, err)
	_, err = s.Reverify(context.Background())
	require.NoError(t, err)
	replacement, err := transport.EnsureVerified(context.Background())
	require.NoError(t, err)
	require.NotSame(t, old, replacement)
	_, err = transport.innerFor(old)
	require.ErrorIs(t, err, errSuperseded, "a request admitted before a refresh retries under the newer state")
	require.Same(t, replacement, transport.state)
	require.Equal(t, 2, built)
}

func TestRefreshRejectsExpiryBeforeTransportConstruction(t *testing.T) {
	s := &Handle{state: testEnclaveState(time.Now().Add(time.Hour), "old"), verify: func() (*verify.Verification, error) {
		return testState(time.Now().Add(-time.Second), "expired"), nil
	}}
	var builds int
	transport, err := bindTransport(s, func(*verify.Verification) (http.RoundTripper, error) {
		builds++
		return roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil }), nil
	}, nil)
	require.NoError(t, err)
	_, err = transport.EnsureVerified(context.Background())
	require.NoError(t, err)
	_, err = verifyNow(s)
	require.ErrorIs(t, err, errFreshnessExpired)
	require.Equal(t, 1, builds)
	require.Equal(t, "old", current(s).CodeTag())
}

func TestLateRejectionDoesNotInvalidateReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var verifications int
		s := &Handle{state: testEnclaveState(time.Now().Add(time.Hour), "old"), verify: func() (*verify.Verification, error) {
			verifications++
			return testState(time.Now().Add(time.Hour), "new"), nil
		}}
		release := make(chan struct{})
		transport, err := bindTransport(s, func(verified *verify.Verification) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				if verified.CodeTag() == "old" {
					<-release
					return nil, errCertMismatch
				}
				return testResponse(), nil
			}), nil
		}, isCertificateError)
		require.NoError(t, err)
		finished := make(chan error, 1)
		go func() {
			req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
			_, err := transport.RoundTrip(req)
			finished <- err
		}()
		synctest.Wait()
		_, err = verifyNow(s)
		require.NoError(t, err)
		close(release)
		require.ErrorIs(t, <-finished, errCertMismatch)
		require.False(t, s.state.rejected)
		require.Equal(t, "new", current(s).CodeTag())
		require.Equal(t, 1, verifications)
	})
}

func TestBoundTransportRechecksStateAfterSlowBuild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Handle{state: testEnclaveState(time.Now().Add(time.Minute), "old"), verify: func() (*verify.Verification, error) {
			return testState(time.Now().Add(time.Hour), "new"), nil
		}}
		var sent []string
		transport, err := bindTransport(s, func(verified *verify.Verification) (http.RoundTripper, error) {
			if verified.CodeTag() == "old" {
				time.Sleep(2 * time.Minute) // the state expires while its transport is built
			}
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				sent = append(sent, verified.CodeTag())
				return testResponse(), nil
			}), nil
		}, nil)
		require.NoError(t, err)
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		_, err = transport.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, []string{"new"}, sent, "a state that expired during the build never authorizes a request")
	})
}

// idleCountingTransport counts CloseIdleConnections calls.
type idleCountingTransport struct {
	http.RoundTripper
	closes int
}

func (t *idleCountingTransport) CloseIdleConnections() { t.closes++ }

func TestFailedRebuildClosesSupersededConnections(t *testing.T) {
	s := &Handle{verify: func() (*verify.Verification, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	}}
	buildErr := errors.New("the new verification endorses no key for this binding")
	first := &idleCountingTransport{RoundTripper: roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil })}
	builds := 0
	transport, err := bindTransport(s, func(*verify.Verification) (http.RoundTripper, error) {
		builds++
		if builds > 1 {
			return nil, buildErr
		}
		return first, nil
	}, nil)
	require.NoError(t, err)
	_, err = transport.EnsureVerified(context.Background())
	require.NoError(t, err)
	_, err = s.Reverify(context.Background())
	require.NoError(t, err)
	_, err = transport.EnsureVerified(context.Background())
	require.ErrorIs(t, err, buildErr)
	require.Equal(t, 1, first.closes, "connections bound to the superseded keys are closed even though no replacement was built")
}
