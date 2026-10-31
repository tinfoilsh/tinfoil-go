package transport

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestPlaintextRequestDoesNotRefresh(t *testing.T) {
	pinning := newTestTransport(t, testState(time.Now().Add(time.Hour), "key"), func() (*verify.Verification, error) {
		t.Error("re-verification cannot make a plaintext URL acceptable")
		return nil, errNoTLS
	}, tlsMode{})
	_, err := (&http.Client{Transport: pinning}).Get("http://enclave.example")
	require.ErrorIs(t, err, errNoTLS)
}

func TestEnsureVerifiedReusesValidVerification(t *testing.T) {
	var verifications int
	transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
		verifications++
		return testState(time.Now().Add(time.Hour), "key"), nil
	}, sendOK)
	for range 2 {
		_, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err)
	}
	require.Equal(t, 1, verifications, "a valid verification is reused")

	_, err := transport.Reverify(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, verifications, "Reverify always verifies")
}

func TestRefreshWaitersCancelIndependentlyWithoutVerificationTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
			<-release
			return testState(time.Now().Add(time.Hour), "key"), nil
		}, sendOK)
		ctx, cancel := context.WithCancel(context.Background())
		canceled, waiting := make(chan error, 1), make(chan error, 1)
		go func() { _, err := transport.EnsureVerified(ctx); canceled <- err }()
		go func() { _, err := transport.Reverify(context.Background()); waiting <- err }()
		synctest.Wait()
		cancel()
		require.ErrorIs(t, <-canceled, context.Canceled)
		time.Sleep(time.Minute)
		select {
		case <-waiting:
			t.Fatal("shared verification must survive caller cancellation and has no SDK timeout")
		default:
		}
		close(release)
		require.NoError(t, <-waiting)
		require.NotNil(t, transport.Current())
	})
}

func TestInitializationRetryIsShared(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts int
		release := make(chan struct{})
		transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
			attempts++
			if attempts == 1 {
				<-release
				return nil, &enclave.NetworkError{Err: errors.New("temporarily unavailable")}
			}
			return testState(time.Now().Add(time.Hour), "fresh"), nil
		}, sendOK)
		results := make(chan error, 8)
		for range cap(results) {
			go func() { _, err := transport.Reverify(context.Background()); results <- err }()
		}
		synctest.Wait()
		close(release)
		for range cap(results) {
			require.NoError(t, <-results)
		}
		require.Equal(t, 2, attempts)
	})
}

func TestRoundTripperFailureFailsVerification(t *testing.T) {
	var verifications int
	newErr := errors.New("the verification endorses no key for this transport")
	transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
		verifications++
		return testState(time.Now().Add(time.Hour), "key"), nil
	}, testMode(func(*verify.Verification) (http.RoundTripper, error) { return nil, newErr }))
	_, err := transport.EnsureVerified(context.Background())
	require.ErrorIs(t, err, newErr)
	req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
	_, err = transport.RoundTrip(req)
	require.ErrorIs(t, err, newErr)
	require.Nil(t, transport.Current(), "a verification the mode can't use is never kept")
	require.Equal(t, 2, verifications, "each attempt verifies once, without a retry")
}

func TestRefreshRejectsExpiredVerification(t *testing.T) {
	transport := newTestTransport(t, testState(time.Now().Add(time.Hour), "old"), func() (*verify.Verification, error) {
		return testState(time.Now().Add(-time.Second), "expired"), nil
	}, sendOK)
	_, err := transport.Reverify(context.Background())
	require.ErrorIs(t, err, enclave.ErrFreshnessExpired)
	require.Equal(t, "old", transport.Current().CodeTag())
	require.True(t, currentValid(transport), "a failed refresh leaves a valid verification in place")
}

func TestRefreshRejectsVerificationThatExpiresDuringCreation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var sent int
		transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
			return testState(time.Now().Add(time.Minute), "key"), nil
		}, testMode(func(*verify.Verification) (http.RoundTripper, error) {
			time.Sleep(2 * time.Minute) // the verification expires while its round tripper is created
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				sent++
				return testResponse(), nil
			}), nil
		}))
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		_, err := transport.RoundTrip(req)
		require.ErrorIs(t, err, enclave.ErrFreshnessExpired)
		require.Zero(t, sent, "a verification that expired before publication never authorizes a request")
		require.Nil(t, transport.Current())
	})
}

func TestLateRejectionDoesNotInvalidateReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var verifications int
		release := make(chan struct{})
		transport := newTestTransport(t, testState(time.Now().Add(time.Hour), "old"), func() (*verify.Verification, error) {
			verifications++
			return testState(time.Now().Add(time.Hour), "new"), nil
		}, testMode(func(verified *verify.Verification) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				if verified.CodeTag() == "old" {
					<-release
					return nil, &peerLacksKeyError{errCertMismatch}
				}
				return testResponse(), nil
			}), nil
		}))
		finished := make(chan error, 1)
		go func() {
			req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
			_, err := transport.RoundTrip(req)
			finished <- err
		}()
		synctest.Wait()
		_, err := transport.Reverify(context.Background())
		require.NoError(t, err)
		close(release)
		require.ErrorIs(t, <-finished, errCertMismatch)
		require.True(t, currentValid(transport), "the replacement stays valid")
		require.Equal(t, "new", transport.Current().CodeTag())
		require.Equal(t, 1, verifications)
	})
}

// idleCountingTransport counts CloseIdleConnections calls.
type idleCountingTransport struct {
	http.RoundTripper
	closes int
}

func (t *idleCountingTransport) CloseIdleConnections() { t.closes++ }

func TestRefreshClosesReplacedConnections(t *testing.T) {
	newErr := errors.New("the new verification endorses no key for this transport")
	var created []*idleCountingTransport
	transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	}, testMode(func(*verify.Verification) (http.RoundTripper, error) {
		if len(created) == 1 {
			created = append(created, nil)
			return nil, newErr
		}
		rt := &idleCountingTransport{RoundTripper: roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil })}
		created = append(created, rt)
		return rt, nil
	}))
	_, err := transport.EnsureVerified(context.Background())
	require.NoError(t, err)
	first := created[0]
	_, err = transport.Reverify(context.Background())
	require.ErrorIs(t, err, newErr)
	require.Zero(t, first.closes, "a failed refresh keeps the current round tripper")
	_, err = transport.Reverify(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, first.closes, "connections tied to the replaced keys are closed")
}
