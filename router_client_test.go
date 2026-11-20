package tinfoil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestNewRouterHTTPClientWritesNoCacheSecretFile(t *testing.T) {
	home := emptyHome(t)
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
	requireEmptyDir(t, home)
}

func TestNewRouterHTTPClientRejectsInvalidOptionsBeforeDiscovery(t *testing.T) {
	// A done context makes discovery itself fail, so only a check made before
	// discovery reports ErrConfiguration.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, opts := range []*RouterOptions{
		{Transport: &TLS{}},
		{Transport: embeddedTLS{}},
		{Transport: EHBP{ProxyURL: "http://proxy.example/v1/"}},
		{Transport: EHBP{ProxyURL: "/v1/"}},
		{Policy: verify.Policy{FreshnessMaxAge: -1}},
	} {
		c, err := NewRouterHTTPClient(ctx, opts)
		require.Nil(t, c)
		require.ErrorIs(t, err, ErrConfiguration)
	}
	for _, proxyURL := range []string{"https://proxy.example/v1/", "http://localhost:8080/v1/"} {
		_, err := NewRouterHTTPClient(ctx, &RouterOptions{Transport: EHBP{ProxyURL: proxyURL}})
		require.ErrorIs(t, err, context.Canceled, "%s passes the checks and reaches discovery", proxyURL)
	}
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
