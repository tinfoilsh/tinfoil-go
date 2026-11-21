package tinfoil

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// These tests check the error model at each public entry point: every error
// is in exactly one SDK category, except the caller's cancellation, which is
// in none.

var errRefused = errors.New("connection refused")

// noError is the expectation of a call that succeeds.
var noError = errors.New("no error")

// serveEveryFetch makes respond answer everything sent through the default
// HTTP client and transport, which every fetch of the SDK and every request
// that EHBP seals use.
func serveEveryFetch(t *testing.T, respond func(*http.Request) (*http.Response, error)) {
	t.Helper()
	client, transport := http.DefaultClient, http.DefaultTransport
	t.Cleanup(func() { http.DefaultClient, http.DefaultTransport = client, transport })
	http.DefaultClient = &http.Client{}
	http.DefaultTransport = roundTripFunc(respond)
}

func respondWith(status int, body io.Reader) func(*http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: make(http.Header), Body: io.NopCloser(body), Request: req}, nil
	}
}

// zeros reads as an endless run of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// failingBody reads data, then fails with err.
type failingBody struct {
	data io.Reader
	err  error
}

func (b *failingBody) Read(p []byte) (int, error) {
	if n, err := b.data.Read(p); err != io.EOF {
		return n, err
	}
	return 0, b.err
}

func (*failingBody) Close() error { return nil }

func hang(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

// A fetchScenario is how every fetch is answered, and the context under which
// the entry point is called.
type fetchScenario struct {
	respond func(*http.Request) (*http.Response, error)
	// ctx is "live", "cancelled", "cancel in flight" or "deadline".
	ctx string
	// want is the category, nil for the caller's cancellation and noError
	// for success; an entry point can override it.
	want error
	// is is an error that the result must match, if any.
	is error
}

var fetchScenarios = map[string]fetchScenario{
	"refused connection": {respond: func(*http.Request) (*http.Response, error) { return nil, errRefused }, ctx: "live", want: ErrNetwork, is: errRefused},
	"503":                {respond: func(req *http.Request) (*http.Response, error) { return respondWith(503, http.NoBody)(req) }, ctx: "live", want: ErrNetwork},
	"oversized body": {respond: func(req *http.Request) (*http.Response, error) {
		return respondWith(200, io.LimitReader(zeros{}, 32<<20+1))(req)
	}, ctx: "live", want: ErrNetwork},
	// What doesn't parse: an attestation document fails verification.
	"verification failure": {respond: func(req *http.Request) (*http.Response, error) {
		return respondWith(200, strings.NewReader("not a document"))(req)
	}, ctx: "live", want: ErrAttestation},
	"caller cancellation":           {respond: hang, ctx: "cancelled", want: nil, is: context.Canceled},
	"caller cancellation in flight": {respond: hang, ctx: "cancel in flight", want: nil, is: context.Canceled},
	"caller deadline":               {respond: hang, ctx: "deadline", want: nil, is: context.DeadlineExceeded},
	"SDK timeout":                   {respond: hang, ctx: "live", want: ErrNetwork},
}

// call calls entry under the scenario's context.
func (s fetchScenario) call(entry func(context.Context) error) error {
	switch s.ctx {
	case "cancelled":
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return entry(ctx)
	case "cancel in flight":
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- entry(ctx) }()
		synctest.Wait()
		cancel()
		return <-done
	case "deadline":
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return entry(ctx)
	default:
		return entry(context.Background())
	}
}

// requireOutcome checks err against want, a category, nil for the caller's
// cancellation or noError, and against is.
func requireOutcome(t *testing.T, err, want, is error) {
	t.Helper()
	if want == noError {
		require.NoError(t, err)
		return
	}
	testutil.RequireCategory(t, err, want)
	if is != nil {
		require.ErrorIs(t, err, is)
	}
}

const testModel = "test-model"

var testCatalog = Catalog{testModel: {Repo: "tinfoilsh/test", Hosts: []string{"replica.example"}}}

// A fetchEntry is a public entry point that fetches over the network.
type fetchEntry struct {
	call func(t *testing.T, ctx context.Context) error
	// override replaces a scenario's expected category.
	override map[string]error
}

func fetchEntries() map[string]fetchEntry {
	unverifiedEnclave := func(t *testing.T, transport Transport) *EnclaveHTTPClient {
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: transport})
		require.NoError(t, err)
		return c
	}
	staticGateway := func(t *testing.T) *GatewayHTTPClient {
		c, err := unverifiedGatewayHTTPClient(&GatewayOptions{Catalog: func() Catalog { return testCatalog }})
		require.NoError(t, err)
		return c
	}
	// A catalog that doesn't parse is a network failure, not an attestation
	// one.
	catalogOverride := map[string]error{"verification failure": ErrNetwork}
	return map[string]fetchEntry{
		"NewEnclaveHTTPClient": {call: func(t *testing.T, ctx context.Context) error {
			_, err := NewEnclaveHTTPClient(ctx, "enclave.example", RepoPin{Repo: "org/repo"}, nil)
			return err
		}},
		"NewEnclaveHTTPClient/EHBP": {call: func(t *testing.T, ctx context.Context) error {
			_, err := NewEnclaveHTTPClient(ctx, "enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{}})
			return err
		}},
		"NewRouterHTTPClient": {call: func(t *testing.T, ctx context.Context) error {
			_, err := NewRouterHTTPClient(ctx, nil)
			return err
		}},
		"NewClient": {call: func(t *testing.T, ctx context.Context) error {
			_, err := NewClient(ctx)
			return err
		}},
		"NewGatewayHTTPClient": {call: func(t *testing.T, ctx context.Context) error {
			_, err := NewGatewayHTTPClient(ctx, &GatewayOptions{URL: "https://gateway.example/v1/"})
			return err
		}, override: catalogOverride},
		"FetchCatalog": {call: func(t *testing.T, ctx context.Context) error {
			_, err := FetchCatalog(ctx, "gateway.example")
			return err
		}, override: catalogOverride},
		"AttestationRelay.FetchAttestation": {call: func(t *testing.T, ctx context.Context) error {
			_, err := AttestationRelay{URL: "https://relay.example"}.FetchAttestation(ctx, "enclave.example", make([]byte, document.NonceSize))
			return err
		}, override: map[string]error{"verification failure": noError}},
		"RouterListRelay.FetchRouterList": {call: func(t *testing.T, ctx context.Context) error {
			_, err := RouterListRelay{URL: "https://relay.example"}.FetchRouterList(ctx)
			return err
		}, override: map[string]error{"verification failure": ErrNetwork}},
		"EnclaveHTTPClient.EnsureVerified": {call: func(t *testing.T, ctx context.Context) error {
			_, err := unverifiedEnclave(t, nil).EnsureVerified(ctx)
			return err
		}},
		"EnclaveHTTPClient.Reverify": {call: func(t *testing.T, ctx context.Context) error {
			_, err := unverifiedEnclave(t, EHBP{}).Reverify(ctx)
			return err
		}},
		"EnclaveHTTPClient.Do": {call: func(t *testing.T, ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://enclave.example/v1/models", nil)
			require.NoError(t, err)
			_, err = unverifiedEnclave(t, EHBP{}).Do(req)
			return err
		}},
		"OpenAIClient": {call: func(t *testing.T, ctx context.Context) error {
			client, err := NewOpenAIClient(unverifiedEnclave(t, nil), nil, option.WithMaxRetries(0))
			require.NoError(t, err)
			_, err = client.Models.List(ctx)
			return err
		}},
		"GatewayHTTPClient.Models": {call: func(t *testing.T, ctx context.Context) error {
			c, err := unverifiedGatewayHTTPClient(&GatewayOptions{URL: "https://gateway.example/v1/"})
			require.NoError(t, err)
			_, err = c.Models(ctx)
			return err
		}, override: catalogOverride},
		"GatewayHTTPClient.EnsureVerified": {call: func(t *testing.T, ctx context.Context) error {
			_, err := staticGateway(t).EnsureVerified(ctx, testModel)
			return err
		}},
		"GatewayHTTPClient.Do": {call: func(t *testing.T, ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://inference-gateway.tinfoil.sh/v1/chat/completions", strings.NewReader(`{"model":"`+testModel+`"}`))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			_, err = staticGateway(t).Do(req)
			return err
		}},
	}
}

func TestEveryFetchingEntryPointReportsOneCategory(t *testing.T) {
	for entryName, entry := range fetchEntries() {
		for scenarioName, scenario := range fetchScenarios {
			t.Run(entryName+"/"+scenarioName, func(t *testing.T) {
				serveEveryFetch(t, scenario.respond)
				synctest.Test(t, func(t *testing.T) {
					err := scenario.call(func(ctx context.Context) error { return entry.call(t, ctx) })
					want, overridden := entry.override[scenarioName]
					if !overridden {
						want = scenario.want
					}
					requireOutcome(t, err, want, scenario.is)
					// A cancellation ends the caller's wait, not the SDK's
					// own work, which ends within its limits.
					time.Sleep(2 * time.Minute)
				})
			})
		}
	}
}

func TestEveryEntryPointReportsBadInputAsAConfigurationError(t *testing.T) {
	serveEveryFetch(t, func(req *http.Request) (*http.Response, error) {
		t.Errorf("bad input is refused before any network I/O, but %s was sent", req.URL)
		return nil, errRefused
	})
	ctx := context.Background()
	gateway, err := unverifiedGatewayHTTPClient(&GatewayOptions{Catalog: func() Catalog { return testCatalog }, ModelPins: map[string]ModelPin{testModel: {Repo: "tinfoilsh/test"}}, PinnedModelsOnly: true})
	require.NoError(t, err)
	enclaveClient, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
	require.NoError(t, err)
	for name, call := range map[string]func() error{
		"NewEnclaveHTTPClient": func() error {
			_, err := NewEnclaveHTTPClient(ctx, "", RepoPin{Repo: "org/repo"}, nil)
			return err
		},
		"NewRouterHTTPClient": func() error {
			_, err := NewRouterHTTPClient(ctx, &RouterOptions{Transport: &TLS{}})
			return err
		},
		"NewGatewayHTTPClient": func() error {
			_, err := NewGatewayHTTPClient(ctx, &GatewayOptions{URL: "http://gateway.example/v1/"})
			return err
		},
		"NewOpenAIClient": func() error {
			_, err := NewOpenAIClient(nil, nil)
			return err
		},
		"FetchCatalog": func() error {
			_, err := FetchCatalog(ctx, "gateway example")
			return err
		},
		"AttestationRelay.FetchAttestation": func() error {
			_, err := AttestationRelay{URL: "http://relay.example"}.FetchAttestation(ctx, "enclave.example", make([]byte, document.NonceSize))
			return err
		},
		"RouterListRelay.FetchRouterList": func() error {
			_, err := RouterListRelay{}.FetchRouterList(ctx)
			return err
		},
		"GatewayHTTPClient.EnsureVerified": func() error {
			_, err := gateway.EnsureVerified(ctx, "unpinned-model")
			return err
		},
		"GatewayHTTPClient.Do": func() error {
			req, err := http.NewRequest(http.MethodPost, "https://inference-gateway.tinfoil.sh/v1/chat/completions", strings.NewReader(`{"model":"unpinned-model"}`))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			_, err = gateway.Do(req)
			return err
		},
		"EnclaveHTTPClient.Do": func() error {
			_, err := enclaveClient.Get("https://elsewhere.example/v1/models")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			testutil.RequireCategory(t, call(), ErrConfiguration)
		})
	}
}

// fetchCallbackCases are the errors that a caller's FetchAttestation and
// FetchRouterList return, and what a constructor reports for them.
func TestConstructorsClassifyEachCallbacksError(t *testing.T) {
	cause := errors.New("relay failed")
	for name, tc := range map[string]struct {
		attestation func(context.Context) ([]byte, error)
		list        func(context.Context) ([]string, error)
		want        error
	}{
		"FetchAttestation fails":                      {attestation: func(context.Context) ([]byte, error) { return nil, cause }, want: ErrNetwork},
		"FetchAttestation cancels by itself":          {attestation: func(context.Context) ([]byte, error) { return nil, context.Canceled }, want: ErrNetwork},
		"FetchAttestation reports a network error":    {attestation: func(context.Context) ([]byte, error) { return nil, errs.Network(cause) }, want: ErrNetwork},
		"FetchAttestation reports a config error":     {attestation: func(context.Context) ([]byte, error) { return nil, errs.Configuration(cause) }, want: ErrConfiguration},
		"FetchAttestation reports an attestation one": {attestation: func(context.Context) ([]byte, error) { return nil, errs.Attestation(cause) }, want: ErrAttestation},
		"FetchAttestation returns no document":        {attestation: func(context.Context) ([]byte, error) { return []byte("not a document"), nil }, want: ErrAttestation},
		"FetchRouterList fails with a category": {
			attestation: func(context.Context) ([]byte, error) { return nil, errors.New("unreachable") },
			list:        func(context.Context) ([]string, error) { return []string{"router.example"}, errs.Configuration(cause) },
			want:        ErrNetwork,
		},
	} {
		t.Run(name, func(t *testing.T) {
			refuseDirectFetches(t)
			synctest.Test(t, func(t *testing.T) {
				fetcher := AttestationFetcherFunc(func(ctx context.Context, _ string, _ []byte) ([]byte, error) { return tc.attestation(ctx) })
				var lister RouterListFetcher = RouterListFetcherFunc(func(context.Context) ([]string, error) { return nil, nil })
				if tc.list != nil {
					lister = RouterListFetcherFunc(tc.list)
				}
				_, err := NewEnclaveHTTPClient(context.Background(), "enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{FetchAttestation: fetcher})
				if tc.list == nil {
					testutil.RequireCategory(t, err, tc.want)
				}
				_, err = NewRouterHTTPClient(context.Background(), &RouterOptions{FetchAttestation: fetcher, FetchRouterList: lister})
				testutil.RequireCategory(t, err, tc.want)
			})
		})
	}
}

// hpkeKey returns a fresh X25519 public key in hex, which EHBP can seal to.
func hpkeKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return hex.EncodeToString(key.PublicKey().Bytes())
}

func testVerification(t *testing.T) *verify.Verification {
	key := hpkeKey(t)
	return verifytest.New(verifytest.Fields{
		FreshnessExpiresAt: time.Now().Add(time.Hour),
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: "tls-key"},
			{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: key},
		},
	})
}

// requestClients returns the plain clients whose requests the request-path
// table sends, each over EHBP to an enclave whose verification v returns and
// check accepts or rejects.
func requestClients(t *testing.T, check func(*verify.Verification) error) map[string]func(*http.Request) (*http.Response, error) {
	verification := testVerification(t)
	attested := func(secret string) attestedClient {
		e := enclave.NewForTestWithCheck("enclave.example", func() (*verify.Verification, error) { return verification, nil }, check)
		a, err := newAttestedClient(keyedTransport(EHBP{}, e), "", secret)
		require.NoError(t, err)
		return a
	}
	enclaveClient := &EnclaveHTTPClient{attestedClient: attested("")}
	enclaveClient.Client = enclaveClient.embedded()
	routerClient := &RouterHTTPClient{attestedClient: attested("cache-secret")}
	routerClient.Client = routerClient.embedded()
	return map[string]func(*http.Request) (*http.Response, error){
		"EnclaveHTTPClient": enclaveClient.Do,
		"RouterHTTPClient":  routerClient.Do,
		// The OpenAI client sends a request of its own with req's method and
		// context, a POST with a JSON body that it can replay or a GET, and
		// reads the response.
		"OpenAIClient": func(req *http.Request) (*http.Response, error) {
			client, err := NewOpenAIClient(enclaveClient, nil, option.WithMaxRetries(0))
			require.NoError(t, err)
			var out map[string]any
			if req.Method == http.MethodGet {
				err = client.Get(req.Context(), "models", nil, &out)
			} else {
				err = client.Post(req.Context(), "chat/completions", map[string]any{"model": "m"}, &out)
			}
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		},
	}
}

func keyRejection(req *http.Request) (*http.Response, error) {
	resp, err := respondWith(http.StatusUnprocessableEntity, strings.NewReader(`{"type":"urn:ietf:params:ehbp:error:key-config","title":"rotated"}`))(req)
	resp.Header.Set("Content-Type", "application/problem+json")
	return resp, err
}

func TestEveryRequestErrorHasOneCategory(t *testing.T) {
	reset := errors.New("connection reset by peer")
	callbackErr := errors.New("unapproved release")
	for name, tc := range map[string]struct {
		respond func(*http.Request) (*http.Response, error)
		check   func(*verify.Verification) error
		// body is the request body, which a POST sends, and nil for a GET.
		body io.Reader
		ctx  string
		want error
		is   error
	}{
		"refused connection":                     {respond: func(*http.Request) (*http.Response, error) { return nil, errRefused }, want: ErrNetwork, is: errRefused},
		"VerificationCheck":                      {check: func(*verify.Verification) error { return callbackErr }, want: ErrAttestation, is: callbackErr},
		"VerificationCheck returns an SDK error": {check: func(*verify.Verification) error { return errs.Network(callbackErr) }, want: ErrAttestation, is: callbackErr},
		"unreplayable body after a key rotation": {respond: keyRejection, body: io.NopCloser(strings.NewReader(`{"model":"m"}`)), want: ErrNetwork},
		"response body read failure": {respond: func(req *http.Request) (*http.Response, error) {
			return respondWith(200, &failingBody{data: strings.NewReader(`{"partial"`), err: reset})(req)
		}, want: ErrNetwork, is: reset},
		"unauthenticated response": {respond: func(req *http.Request) (*http.Response, error) {
			resp, err := respondWith(200, strings.NewReader("forged"))(req)
			resp.Header.Set("Ehbp-Response-Nonce", "not hex")
			return resp, err
		}, body: strings.NewReader(`{"model":"m"}`), want: ErrAttestation},
		"caller cancellation": {respond: hang, ctx: "cancelled", is: context.Canceled},
		"caller deadline":     {respond: hang, ctx: "deadline", is: context.DeadlineExceeded},
	} {
		for clientName, do := range requestClients(t, func(*verify.Verification) error { return nil }) {
			t.Run(clientName+"/"+name, func(t *testing.T) {
				if tc.check != nil {
					do = requestClients(t, tc.check)[clientName]
				}
				respond := tc.respond
				if respond == nil {
					respond = func(*http.Request) (*http.Response, error) {
						t.Error("a rejected enclave is sent nothing")
						return nil, errRefused
					}
				}
				serveEveryFetch(t, respond)
				synctest.Test(t, func(t *testing.T) {
					err := fetchScenario{ctx: tc.ctx}.call(func(ctx context.Context) error {
						method, body := http.MethodGet, tc.body
						if body != nil {
							method = http.MethodPost
						}
						req, err := http.NewRequestWithContext(ctx, method, "https://enclave.example/v1/chat/completions", body)
						require.NoError(t, err)
						if body != nil {
							req.GetBody = nil
						}
						resp, err := do(req)
						if err == nil {
							_, err = io.ReadAll(resp.Body)
							resp.Body.Close()
						}
						return err
					})
					requireOutcome(t, err, tc.want, tc.is)
				})
			})
		}
	}
}

// An upstream API error is the wrapped library's, in no SDK category.
func TestAnAPIErrorPassesThrough(t *testing.T) {
	serveEveryFetch(t, func(req *http.Request) (*http.Response, error) {
		resp, err := respondWith(http.StatusTooManyRequests, strings.NewReader(`{"error":{"message":"slow down"}}`))(req)
		resp.Header.Set("Content-Type", "application/json")
		return resp, err
	})
	do := requestClients(t, nil)["OpenAIClient"]
	req, err := http.NewRequest(http.MethodGet, "https://enclave.example/v1/models", nil)
	require.NoError(t, err)
	_, err = do(req)
	var apiErr *openai.Error
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusTooManyRequests, apiErr.StatusCode)
	testutil.RequireCategory(t, err, nil)
}

// The gateway client's backstop classifies what no layer below it does, such
// as a request body that fails to read.
func TestTheGatewayClientsBackstopClassifiesARequestError(t *testing.T) {
	serveEveryFetch(t, func(req *http.Request) (*http.Response, error) {
		t.Errorf("a body that can't be read is never sent, but %s was", req.URL)
		return nil, errRefused
	})
	reset := errors.New("connection reset by peer")
	gateway, err := unverifiedGatewayHTTPClient(&GatewayOptions{Catalog: func() Catalog { return testCatalog }})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, "https://inference-gateway.tinfoil.sh/v1/chat/completions", &failingBody{data: strings.NewReader(`{"model":`), err: reset})
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	_, err = gateway.Do(req)
	testutil.RequireCategory(t, err, ErrNetwork)
	require.ErrorIs(t, err, reset)
}
