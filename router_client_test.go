package tinfoil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewRouterHTTPClientResolvesTheCacheSecret(t *testing.T) {
	path := unsetCacheSecretSources(t)
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	synctest.Test(t, func(t *testing.T) {
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "atc.tinfoil.sh" {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("[]")), Request: req}, nil
			}
			return nil, errors.New("no network in this test")
		})}
		_, err := NewRouterHTTPClient(context.Background(), nil)
		require.Error(t, err, "the fallback can't be verified")
	})
	_, err := os.Stat(path)
	require.NoError(t, err, "the router route provisions the shared secret")
}

func TestNewRouterHTTPClientRejectsInvalidOptionsBeforeDiscovery(t *testing.T) {
	// A done context makes discovery itself fail, so only a check made before
	// discovery reports a ConfigurationError.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, opts := range []*RouterOptions{
		{TransportMode: "quic"},
		{TransportMode: TransportModeEHBP, BaseURL: "http://proxy.example/v1/"},
		{BaseURL: "https://proxy.example/v1/"},
		{TransportMode: TransportModeTLS, BaseURL: "https://proxy.example/v1/"},
		{Verifier: callerAuthorizedVerifier(t)},
	} {
		c, err := NewRouterHTTPClient(ctx, opts)
		require.Nil(t, c)
		var config *ConfigurationError
		require.ErrorAs(t, err, &config)
	}
	_, err := NewRouterHTTPClient(ctx, &RouterOptions{BaseURL: "https://proxy.example/v1/"})
	require.ErrorContains(t, err, "requires TransportModeEHBP", "a proxy never downgrades the default mode silently")
	_, err = NewRouterHTTPClient(ctx, &RouterOptions{TransportMode: TransportModeEHBP, BaseURL: "http://localhost:8080/v1/"})
	require.ErrorIs(t, err, context.Canceled, "a loopback proxy passes the checks and reaches discovery")
}

func TestNewRouterHTTPClientVerifiesTheFallbackUnderItsContext(t *testing.T) {
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		defer func() {
			close(release)
			time.Sleep(time.Minute) // let the abandoned verification finish its retries
		}()
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "atc.tinfoil.sh" {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("[]")), Request: req}, nil
			}
			<-release // the fallback's attestation never arrives
			return nil, errors.New("unreachable")
		})}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := NewRouterHTTPClient(ctx, nil)
			done <- err
		}()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.DeadlineExceeded)
		case <-time.After(time.Minute):
			t.Fatal("NewRouterHTTPClient kept verifying the fallback after its context expired")
		}
	})
}
