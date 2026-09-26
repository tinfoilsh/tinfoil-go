package document

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

type fetchTransport func(*http.Request) (*http.Response, error)

func (f fetchTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchSizeLimitAndRedirects(t *testing.T) {
	const limit = 32 << 20
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	for _, size := range []int{limit, limit + 1} {
		redirects := 0
		http.DefaultClient = &http.Client{
			Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/redirect" {
					redirects++
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"/redirect"}}, Body: http.NoBody}, nil
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", size)))}, nil
			}),
		}
		body, err := Fetch("enclave.example", testNonce())
		require.Equal(t, 1, redirects)
		if size > limit {
			require.ErrorContains(t, err, "exceeds 33554432 bytes")
			require.Nil(t, body)
		} else {
			require.NoError(t, err)
			require.Len(t, body, size)
		}
	}
}

func TestFetchTimeout(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	for _, timeout := range []time.Duration{0, time.Second} {
		synctest.Test(t, func(t *testing.T) {
			http.DefaultClient = &http.Client{Timeout: timeout, Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
				body, writer := io.Pipe()
				go func() {
					<-r.Context().Done()
					writer.CloseWithError(r.Context().Err())
				}()
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			})}
			start := time.Now()
			_, err := Fetch("enclave.example", testNonce())
			require.ErrorIs(t, err, context.DeadlineExceeded)
			if timeout == 0 {
				timeout = 30 * time.Second
			}
			require.Equal(t, timeout, time.Since(start))
		})
	}
}

func TestFetchRejectsNonHTTPSRedirect(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	var schemes []string
	http.DefaultClient = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
		Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
			schemes = append(schemes, r.URL.Scheme)
			if r.URL.Scheme != "https" {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("plaintext document"))}, nil
			}
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"http://enclave.example/redirect"}}, Body: http.NoBody}, nil
		}),
	}
	_, err := Fetch("enclave.example", testNonce())
	require.ErrorContains(t, err, "refusing redirect to non-HTTPS URL")
	require.Equal(t, []string{"https"}, schemes)
}

func TestFetchKeepsDefaultRedirectLimit(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	requests := 0
	http.DefaultClient = &http.Client{Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"/loop"}}, Body: http.NoBody}, nil
	})}
	_, err := Fetch("enclave.example", testNonce())
	require.ErrorContains(t, err, "stopped after 10 redirects")
	require.Equal(t, 10, requests)
}

func TestFetchUsesFreshConnectionAfterCutover(t *testing.T) {
	for _, tc := range []struct {
		name             string
		http2            bool
		defaultTransport bool
	}{
		{"HTTP1/client_transport", false, false},
		{"HTTP1/default_transport", false, true},
		{"HTTP2/client_transport", true, false},
		{"HTTP2/default_transport", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newReplica := func(name string) *httptest.Server {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.WriteString(w, name+" "+r.Proto)
				}))
				server.EnableHTTP2 = tc.http2
				server.StartTLS()
				t.Cleanup(server.Close)
				return server
			}
			oldServer, newServer := newReplica("old"), newReplica("new")
			var address atomic.Value
			address.Store(oldServer.Listener.Addr().String())
			transport := oldServer.Client().Transport.(*http.Transport)
			transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address.Load().(string))
			}
			originalClient, originalTransport := http.DefaultClient, http.DefaultTransport
			http.DefaultClient = &http.Client{Transport: transport}
			if tc.defaultTransport {
				http.DefaultClient.Transport = nil
				http.DefaultTransport = transport
			}
			t.Cleanup(func() {
				transport.CloseIdleConnections()
				http.DefaultClient, http.DefaultTransport = originalClient, originalTransport
			})
			protocol := "HTTP/1.1"
			if tc.http2 {
				protocol = "HTTP/2.0"
			}
			sharedFetch := func() string {
				response, err := http.DefaultClient.Get(oldServer.URL)
				require.NoError(t, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				return string(body)
			}
			require.Equal(t, "old "+protocol, sharedFetch())
			address.Store(newServer.Listener.Addr().String())
			host := strings.TrimPrefix(oldServer.URL, "https://")
			for _, relay := range []string{"", host} {
				body, err := FetchVia(host, relay, testNonce())
				require.NoError(t, err)
				require.Equal(t, "new "+protocol, string(body))
			}
			require.Equal(t, "old "+protocol, sharedFetch(), "attestation must not close the shared connection pool")
		})
	}
}
