package tinfoil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

func routerClient(t *testing.T, host string, transport http.RoundTripper) *enclaveClient {
	t.Helper()
	secure, err := client.NewSecureClient(host, "org/repo", nil)
	require.NoError(t, err)
	return &enclaveClient{secure: secure, transport: transport}
}

func TestRouterRecoverySelectsIndependentClient(t *testing.T) {
	for _, proxy := range []string{"", "http://proxy.example"} {
		t.Run(proxy, func(t *testing.T) {
			first, last := errors.New("old key"), errors.New("replacement unavailable")
			for _, recoveryErr := range []error{nil, last} {
				var sends, selections int
				old := routerClient(t, "old.example", roundTripFunc(func(req *http.Request) (*http.Response, error) {
					sends++
					req.Body.Close()
					return nil, testKeyRejection{first}
				}))
				next := routerClient(t, "next.example", roundTripFunc(func(req *http.Request) (*http.Response, error) {
					sends++
					wantHost := "next.example"
					if proxy != "" {
						wantHost = "proxy.example"
					}
					require.Equal(t, wantHost, req.URL.Host)
					require.Equal(t, wantHost, req.Host)
					require.Equal(t, "/v1/chat?stream=true", req.URL.RequestURI())
					require.Equal(t, "Bearer test", req.Header.Get("Authorization"))
					body, err := io.ReadAll(req.Body)
					req.Body.Close()
					require.NoError(t, err)
					require.Equal(t, "payload", string(body))
					return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
				}))
				origins, err := allowedOrigins(old.secure.Enclave(), proxy)
				require.NoError(t, err)
				transport := &routerTransport{selected: old, origins: origins, proxy: proxy, selectNew: func() (*enclaveClient, error) {
					selections++
					return next, recoveryErr
				}}
				target := "https://old.example"
				if proxy != "" {
					target = proxy
				}
				req, _ := http.NewRequest(http.MethodPost, target+"/v1/chat?stream=true", strings.NewReader("payload"))
				req.Header.Set("Authorization", "Bearer test")
				_, err = transport.RoundTrip(req)
				require.Equal(t, 1, selections)
				require.Equal(t, "old.example", old.secure.Enclave(), "selection cannot mutate the original client")
				require.Equal(t, target+"/v1/chat?stream=true", req.URL.String())
				if recoveryErr != nil {
					require.ErrorIs(t, err, first)
					require.ErrorIs(t, err, last)
					require.Same(t, old, transport.current())
					require.Equal(t, 1, sends)
					continue
				}
				require.NoError(t, err)
				require.Same(t, next, transport.current())
				require.Equal(t, 2, sends)
				retry, err := resetRequestBody(req)
				require.NoError(t, err)
				_, err = transport.RoundTrip(retry)
				require.NoError(t, err, "provider requests still using the initial base URL reach the selected client")
				require.Equal(t, 1, selections)
				for _, target := range []string{"https://foreign.example", "http://next.example"} {
					req, _ := http.NewRequest(http.MethodGet, target, nil)
					_, err := transport.RoundTrip(req)
					var config *ConfigurationError
					require.ErrorAs(t, err, &config)
				}
			}
		})
	}
}

func TestRouterSelectionIsShared(t *testing.T) {
	for _, failure := range []error{nil, errors.New("setup failed")} {
		synctest.Test(t, func(t *testing.T) {
			old, next := routerClient(t, "old.example", nil), routerClient(t, "next.example", nil)
			release := make(chan struct{})
			var selections int
			transport := &routerTransport{selected: old, selectNew: func() (*enclaveClient, error) {
				selections++
				<-release
				return next, failure
			}}
			ctx, cancel := context.WithCancel(context.Background())
			canceled, waiting := make(chan error, 1), make(chan error, 8)
			go func() { _, err := transport.reselect(ctx, old); canceled <- err }()
			for range cap(waiting) {
				go func() { _, err := transport.reselect(context.Background(), old); waiting <- err }()
			}
			synctest.Wait()
			cancel()
			require.ErrorIs(t, <-canceled, context.Canceled)
			require.Equal(t, 1, selections)
			close(release)
			for range cap(waiting) {
				require.ErrorIs(t, <-waiting, failure)
			}
			if failure == nil {
				selected, err := transport.reselect(context.Background(), old)
				require.NoError(t, err)
				require.Same(t, next, selected, "late rejection reuses the completed selection")
				require.Equal(t, 1, selections)
			} else {
				require.Same(t, old, transport.current())
				require.Nil(t, transport.selecting)
			}
		})
	}
}

func TestRouterSelectionBindsEHBPKeyAndDestination(t *testing.T) {
	const proxy = "http://proxy.example"
	for _, destination := range []string{"", proxy} {
		t.Run(destination, func(t *testing.T) {
			identity, err := ehbpidentity.NewIdentity()
			require.NoError(t, err)
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if destination == "" {
					require.Equal(t, "next.example", req.URL.Host)
				} else {
					require.Equal(t, "proxy.example", req.URL.Host)
					require.Equal(t, "https://next.example", req.Header.Get(enclaveURLHeader))
				}
				response := httptest.NewRecorder()
				identity.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					require.NoError(t, err)
					require.Equal(t, "payload", string(body))
					_, _ = io.WriteString(w, "ok")
				})).ServeHTTP(response, req)
				return response.Result(), nil
			})
			verifier := transportVerifierFunc(func(build func(*client.VerifiedDocumentV3) (http.RoundTripper, error), _ func(error) bool) (http.RoundTripper, error) {
				return build(&client.VerifiedDocumentV3{EnclaveHost: "next.example", CryptoMaterial: []document.CryptoMaterialItem{{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: identity.MarshalPublicKeyHex()}}})
			})
			hc, err := ehbpHTTPClient(verifier, destination)
			require.NoError(t, err)
			old := routerClient(t, "old.example", roundTripFunc(func(req *http.Request) (*http.Response, error) {
				req.Body.Close()
				return nil, testKeyRejection{errors.New("rotated")}
			}))
			next := routerClient(t, "next.example", hc.Transport)
			origins, err := allowedOrigins(old.secure.Enclave(), destination)
			require.NoError(t, err)
			transport := &routerTransport{selected: old, proxy: destination, origins: origins, selectNew: func() (*enclaveClient, error) { return next, nil }}
			target := "https://old.example"
			if destination != "" {
				target = destination
			}
			req, _ := http.NewRequest(http.MethodPost, target+"/v1/chat", strings.NewReader("payload"))
			response, err := transport.RoundTrip(req)
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err)
			require.Equal(t, "ok", string(body))
		})
	}
}
