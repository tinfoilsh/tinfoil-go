package fetch

import (
	"context"
	"encoding/hex"
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
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

func TestFetchReportsSDKIdentity(t *testing.T) {
	const responseBody = "attestation response"
	requests := make(chan *http.Request, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		_, _ = io.WriteString(w, responseBody)
	}))
	defer server.Close()
	original := http.DefaultClient
	http.DefaultClient = server.Client()
	t.Cleanup(func() { http.DefaultClient = original })
	host := strings.TrimPrefix(server.URL, "https://")
	for _, relay := range []bool{false, true} {
		var body []byte
		var err error
		if relay {
			body, err = Relayed(t.Context(), "https://"+host, "enclave.example", testNonce())
		} else {
			body, err = Document(t.Context(), host, testNonce())
		}
		require.NoError(t, err)
		require.Equal(t, responseBody, string(body))
		request := <-requests
		require.Equal(t, "/.well-known/tinfoil-attestation", request.URL.Path)
		require.Equal(t, hex.EncodeToString(testNonce()), request.URL.Query().Get("nonce"))
		require.Equal(t, "tinfoil-go", request.Header.Get("Tinfoil-SDK"))
		require.Equal(t, sdkinfo.Version(), request.Header.Get("Tinfoil-SDK-Version"))
		if relay {
			require.Equal(t, "enclave.example", request.URL.Query().Get("enclave"))
		} else {
			require.Empty(t, request.URL.Query().Get("enclave"))
		}
	}
}

// URL is the wire format other SDKs fetch with too, so it rejects anything
// but a bare host rather than building a request to the wrong place.
func TestURL(t *testing.T) {
	nonce := hex.EncodeToString(testNonce())
	direct, err := URL("enclave.example", "", testNonce())
	require.NoError(t, err)
	require.Equal(t, "https://enclave.example/.well-known/tinfoil-attestation?nonce="+nonce, direct)
	relayed, err := URL("enclave.example", "relay.example:8443", testNonce())
	require.NoError(t, err)
	require.Equal(t, "https://relay.example:8443/.well-known/tinfoil-attestation?nonce="+nonce+"&enclave=enclave.example", relayed)

	for _, bad := range []string{"https://enclave.example", "enclave.example/path", "user@enclave.example", "enclave.example:port", "enclave.example?x=1"} {
		_, err = URL(bad, "", testNonce())
		require.Error(t, err, bad)
		_, err = URL("enclave.example", bad, testNonce())
		require.Error(t, err, "relay "+bad)
	}
	_, err = URL("", "", testNonce())
	require.Error(t, err)
	_, err = URL("enclave.example", "", testNonce()[1:])
	require.Error(t, err)

	// Document reports a URL it cannot build as the caller's configuration.
	_, err = Document(t.Context(), "https://enclave.example", testNonce())
	require.ErrorIs(t, err, errs.ErrConfiguration)
}

// RelayURL joins the attestation path under the relay's mount path, so a
// trailing slash makes no difference.
func TestRelayURL(t *testing.T) {
	query := "?nonce=" + hex.EncodeToString(testNonce()) + "&enclave="
	for relay, want := range map[string]string{
		"https://relay.example":           "https://relay.example/.well-known/tinfoil-attestation",
		"https://relay.example/":          "https://relay.example/.well-known/tinfoil-attestation",
		"https://relay.example/tinfoil":   "https://relay.example/tinfoil/.well-known/tinfoil-attestation",
		"https://relay.example/tinfoil/":  "https://relay.example/tinfoil/.well-known/tinfoil-attestation",
		"https://relay.example:8443/a/b":  "https://relay.example:8443/a/b/.well-known/tinfoil-attestation",
		"http://localhost:8080/attest/":   "http://localhost:8080/attest/.well-known/tinfoil-attestation",
		"https://relay.example/a%2Fb/":    "https://relay.example/a%2Fb/.well-known/tinfoil-attestation",
		"https://relay.example/tin foil/": "https://relay.example/tin%20foil/.well-known/tinfoil-attestation",
	} {
		got, err := RelayURL(relay, "enclave.example", testNonce())
		require.NoError(t, err, relay)
		require.Equal(t, want+query+"enclave.example", got, relay)
	}
	got, err := RelayURL("https://relay.example", "enclave.example:8443", testNonce())
	require.NoError(t, err)
	require.Equal(t, "https://relay.example/.well-known/tinfoil-attestation"+query+"enclave.example%3A8443", got, "the enclave is query-escaped")

	for _, bad := range []string{"", "relay.example", "/relay", "ftp://relay.example", "https://user@relay.example", "https://relay.example?", "https://relay.example/?a=1", "https://relay.example#", "https:relay.example"} {
		_, err := RelayURL(bad, "enclave.example", testNonce())
		require.Error(t, err, bad)
	}
	for _, bad := range []string{"", "https://enclave.example", "enclave.example/path"} {
		_, err := RelayURL("https://relay.example", bad, testNonce())
		require.Error(t, err, "enclave %q", bad)
	}
	_, err = RelayURL("https://relay.example", "enclave.example", testNonce()[1:])
	require.Error(t, err)
	_, err = Relayed(t.Context(), "https://relay.example?", "enclave.example", testNonce())
	require.ErrorIs(t, err, errs.ErrConfiguration)
	_, err = RelayURL("https://user:secret@relay.example", "enclave.example", testNonce())
	require.NotContains(t, err.Error(), "secret", "errors don't echo the URL")
}

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
		body, err := Document(t.Context(), "enclave.example", testNonce())
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
			_, err := Document(t.Context(), "enclave.example", testNonce())
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.ErrorIs(t, err, errs.ErrNetwork, "a limit that isn't the caller's is a network error")
			if timeout == 0 {
				timeout = 30 * time.Second
			}
			require.Equal(t, timeout, time.Since(start))
		})
	}
}

func TestFetchHonorsCallerDeadline(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	synctest.Test(t, func(t *testing.T) {
		http.DefaultClient = &http.Client{Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
			body, writer := io.Pipe()
			go func() {
				<-r.Context().Done()
				writer.CloseWithError(r.Context().Err())
			}()
			return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
		})}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		start := time.Now()
		_, err := Document(ctx, "enclave.example", testNonce())
		require.ErrorIs(t, err, context.DeadlineExceeded, "the caller's deadline")
		require.NotErrorIs(t, err, errs.ErrNetwork, "the caller's deadline has no category")
		require.Equal(t, 5*time.Second, time.Since(start), "a caller deadline shorter than the cap applies")
	})
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
	_, err := Document(t.Context(), "enclave.example", testNonce())
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
	_, err := Document(t.Context(), "enclave.example", testNonce())
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
			for _, relayed := range []bool{false, true} {
				var body []byte
				var err error
				if relayed {
					body, err = Relayed(t.Context(), oldServer.URL, host, testNonce())
				} else {
					body, err = Document(t.Context(), host, testNonce())
				}
				require.NoError(t, err)
				require.Equal(t, "new "+protocol, string(body))
			}
			require.Equal(t, "old "+protocol, sharedFetch(), "attestation must not close the shared connection pool")
		})
	}
}

func testNonce() []byte {
	nonce := make([]byte, document.NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}
