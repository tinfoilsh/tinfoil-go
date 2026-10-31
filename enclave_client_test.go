package tinfoil

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// callerAuthorizedVerifier authorizes configs itself, so it can't verify
// against a repository pin.
func callerAuthorizedVerifier(t *testing.T) *verify.Verifier {
	t.Helper()
	v, err := verify.NewVerifier(verify.WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return nil }))
	require.NoError(t, err)
	return v
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestNewEnclaveHTTPClientRejectsInvalidOptions(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Errorf("invalid options sent %s %s", req.Method, req.URL)
		return nil, errors.New("no network in this test")
	})
	for name, tc := range map[string]struct {
		host, repo string
		opts       *EnclaveOptions
	}{
		"no host":                                 {"", "org/repo", nil},
		"unknown transport mode":                  {"enclave.example", "org/repo", &EnclaveOptions{TransportMode: "quic"}},
		"plaintext remote proxy":                  {"enclave.example", "org/repo", &EnclaveOptions{TransportMode: TransportModeEHBP, BaseURL: "http://proxy.example/v1/"}},
		"TLS through a loopback proxy":            {"enclave.example", "org/repo", &EnclaveOptions{BaseURL: "http://localhost:8080/v1/"}},
		"relative base URL":                       {"enclave.example", "org/repo", &EnclaveOptions{BaseURL: "/v1/"}},
		"TLS through a proxy":                     {"enclave.example", "org/repo", &EnclaveOptions{BaseURL: "https://proxy.example/v1/"}},
		"invalid repository":                      {"enclave.example", "not a reference", nil},
		"config authorizer with a repository pin": {"enclave.example", "org/repo", &EnclaveOptions{Verifier: callerAuthorizedVerifier(t)}},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewEnclaveHTTPClient(t.Context(), tc.host, tc.repo, tc.opts)
			require.Nil(t, c)
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
		})
	}
}

func TestConstructorsVerifyBeforeReturning(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	unreachable := errors.New("no network in this test")
	synctest.Test(t, func(t *testing.T) {
		var mu sync.Mutex
		var requested []string
		http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			defer mu.Unlock()
			requested = append(requested, req.URL.Host)
			return nil, unreachable
		})
		hosts := func() []string {
			mu.Lock()
			defer mu.Unlock()
			seen := requested
			requested = nil
			return seen
		}

		enclaveClient, err := NewEnclaveHTTPClient(context.Background(), "enclave.example", "org/repo", nil)
		require.Nil(t, enclaveClient)
		require.ErrorIs(t, err, unreachable)
		require.Contains(t, hosts(), "enclave.example", "the enclave is verified before the client is returned")

		gw, err := NewGatewayHTTPClient(context.Background(), &GatewayOptions{URL: "https://gateway.example/v1/"})
		require.Nil(t, gw)
		require.ErrorIs(t, err, unreachable)
		require.Equal(t, []string{"gateway.example"}, hosts(), "the catalog is fetched before the client is returned")

		catalog := Catalog{"pinned": {Repo: "tinfoilsh/pinned", Hosts: []string{"replica.example"}}}
		gw, err = NewGatewayHTTPClient(context.Background(), &GatewayOptions{
			Catalog: func() Catalog { return catalog },
			ModelPins: map[string]ModelPin{
				"pinned": {Repo: "tinfoilsh/pinned@v1"},
				"absent": {Repo: "tinfoilsh/absent"},
			},
		})
		require.NoError(t, err, "pins may name models the catalog doesn't list")
		require.Empty(t, hosts(), "with a supplied catalog, nothing is fetched")
		require.Empty(t, gw.Current(), "a model's replicas are verified on its first request")
	})
}

// unsetCacheSecretSources points the cache-secret lookup at an empty home
// and no environment value, and returns where it would persist the secret.
func unsetCacheSecretSources(t *testing.T) string {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TINFOIL_USER_CACHE_SECRET", "")
	return filepath.Join(home, ".tinfoil", "user_cache_secret")
}

func TestNewEnclaveHTTPClientResolvesNoCacheSecret(t *testing.T) {
	path := unsetCacheSecretSources(t)
	_, err := unverifiedEnclaveHTTPClient("enclave.example", "org/repo", nil)
	require.NoError(t, err)
	_, err = os.Stat(filepath.Dir(path))
	require.ErrorIs(t, err, fs.ErrNotExist, "only Tinfoil's inference routes provision the shared secret")
}

func TestEnclaveHTTPClientReportsItsEnclaveAndRepo(t *testing.T) {
	repo := "org/repo@v1@sha256:" + strings.Repeat("a", 64)
	c, err := unverifiedEnclaveHTTPClient("enclave.example:8443", repo, &EnclaveOptions{TransportMode: TransportModeEHBP, BaseURL: "https://proxy.example/v1/"})
	require.NoError(t, err)
	require.Equal(t, "enclave.example:8443", c.Enclave(), "the enclave, not the proxy")
	require.Equal(t, repo, c.Repo(), "with its pins")

	authorized, err := unverifiedEnclaveHTTPClient("enclave.example", "", &EnclaveOptions{Verifier: callerAuthorizedVerifier(t)})
	require.NoError(t, err)
	require.Empty(t, authorized.Repo())
}

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
	for _, opts := range []*EnclaveOptions{
		{TransportMode: "quic"},
		{BaseURL: "http://proxy.example/v1/"},
		{TransportMode: TransportModeTLS, BaseURL: "https://proxy.example/v1/"},
		{Verifier: callerAuthorizedVerifier(t)},
	} {
		c, err := NewRouterHTTPClient(ctx, opts)
		require.Nil(t, c)
		var config *ConfigurationError
		require.ErrorAs(t, err, &config)
	}
	_, err := NewRouterHTTPClient(ctx, &EnclaveOptions{BaseURL: "http://localhost:8080/v1/"})
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

func TestTransportModeDefaultsToTheRoutes(t *testing.T) {
	for _, tc := range []struct {
		mode         TransportMode
		routeDefault TransportMode
		want         TransportMode
	}{
		{"", TransportModeTLS, TransportModeTLS},
		{"", TransportModeEHBP, TransportModeEHBP},
		{TransportModeTLS, TransportModeEHBP, TransportModeTLS},
		{TransportModeEHBP, TransportModeTLS, TransportModeEHBP},
	} {
		got, err := tc.mode.resolve(tc.routeDefault)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
	}
}

func TestKeyedTransportFollowsTheMode(t *testing.T) {
	e := enclave.NewForTest("enclave.example", func() (*verify.Verification, error) {
		t.Error("each transport mode refuses its request before verifying")
		return nil, errors.New("unreachable")
	})
	upgrade, err := http.NewRequest(http.MethodGet, "https://enclave.example/v1/realtime", nil)
	require.NoError(t, err)
	upgrade.Header.Set("Upgrade", "websocket")
	plaintext, err := http.NewRequest(http.MethodGet, "http://enclave.example/v1/models", nil)
	require.NoError(t, err)
	_, err = keyedTransport(TransportModeEHBP, e).RoundTrip(upgrade)
	require.ErrorContains(t, err, "EHBP seals only request and response bodies")
	_, err = keyedTransport(TransportModeTLS, e).RoundTrip(plaintext)
	require.ErrorContains(t, err, "requires an HTTPS request")
}

func TestEnclaveHTTPClientUsesItsTransportMode(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	synctest.Test(t, func(t *testing.T) {
		var fetches int
		http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			fetches++
			return nil, errors.New("no network in this test")
		})
		upgrade := func() *http.Request {
			req, err := http.NewRequest(http.MethodGet, "https://enclave.example/v1/realtime", nil)
			require.NoError(t, err)
			req.Header.Set("Upgrade", "websocket")
			return req
		}
		sealed, err := unverifiedEnclaveHTTPClient("enclave.example", "org/repo", &EnclaveOptions{TransportMode: TransportModeEHBP})
		require.NoError(t, err)
		_, err = sealed.Do(upgrade())
		require.ErrorContains(t, err, "EHBP seals only request and response bodies")
		require.Zero(t, fetches, "EHBP refuses an upgrade before verifying")

		pinned, err := unverifiedEnclaveHTTPClient("enclave.example", "org/repo", nil)
		require.NoError(t, err)
		_, err = pinned.Do(upgrade())
		require.Error(t, err)
		require.NotContains(t, err.Error(), "EHBP seals only")
		require.Positive(t, fetches, "TLS carries the upgrade, so it verifies first")
	})
}

func TestGatewayHTTPClientServesPinnedModels(t *testing.T) {
	catalog := Catalog{
		"pinned":   {Repo: "tinfoilsh/pinned", Hosts: []string{"a.example"}},
		"unpinned": {Repo: "tinfoilsh/unpinned", Hosts: []string{"b.example"}},
	}
	gw, err := unverifiedGatewayHTTPClient(&GatewayOptions{
		Catalog:          func() Catalog { return catalog },
		ModelPins:        map[string]ModelPin{"pinned": {Repo: "tinfoilsh/pinned@v1"}},
		PinnedModelsOnly: true,
		UserCacheSecret:  "test-secret",
	})
	require.NoError(t, err)
	require.Equal(t, "https://inference-gateway.tinfoil.sh/v1/", gw.BaseURL())
	models, err := gw.Models(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"pinned"}, models)
	require.Empty(t, gw.Current(), "no replica is verified before it is used")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = gw.Models(canceled)
	require.ErrorIs(t, err, context.Canceled, "a canceled context fails even with the catalog at hand")
}

func TestNewGatewayHTTPClientRejectsInvalidOptions(t *testing.T) {
	catalog := func() Catalog { return Catalog{} }
	for name, opts := range map[string]*GatewayOptions{
		"plaintext URL":            {URL: "http://gateway.example/v1/", Catalog: catalog},
		"pinned-only without pins": {PinnedModelsOnly: true, Catalog: catalog},
		"pin outside tinfoilsh":    {ModelPins: map[string]ModelPin{"m": {Repo: "acme/m"}}, Catalog: catalog},
		"invalid pin reference":    {ModelPins: map[string]ModelPin{"m": {Repo: "tinfoilsh/m@"}}, Catalog: catalog},
		"caller-authorized config": {Verifier: callerAuthorizedVerifier(t), Catalog: catalog},
		"caller-authorized pin":    {ModelPins: map[string]ModelPin{"m": {Repo: "tinfoilsh/m", Verifier: callerAuthorizedVerifier(t)}}, Catalog: catalog},
	} {
		t.Run(name, func(t *testing.T) {
			gw, err := NewGatewayHTTPClient(t.Context(), opts)
			require.Nil(t, gw)
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
		})
	}
}

func TestLiveRouterClient(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	apiKey := os.Getenv("TINFOIL_API_KEY")
	for _, mode := range []TransportMode{TransportModeEHBP, TransportModeTLS} {
		t.Run(string(mode), func(t *testing.T) {
			oc, err := NewRouterOpenAIClient(context.Background(), &EnclaveOptions{TransportMode: mode, UserCacheSecret: "go-live-integration-cache-secret"}, option.WithAPIKey(apiKey))
			require.NoError(t, err)
			c := oc.HTTPClient()
			verified, err := c.EnsureVerified(context.Background())
			require.NoError(t, err)
			require.Equal(t, verified.FreshnessExpiresAt(), c.Current().FreshnessExpiresAt(), "a valid verification is reused")
			require.Equal(t, "https://"+c.Enclave()+"/", c.BaseURL(), "Enclave is the router discovery chose")
			require.Equal(t, "tinfoilsh/confidential-model-router", c.Repo())

			completion, err := oc.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
				Model:    "llama3-3-70b",
				Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Is this a test?")},
			})
			require.NoError(t, err)
			require.NotEmpty(t, completion.Choices)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.BaseURL()+"v1/models", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+apiKey)
			resp, err := c.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestLiveNewEnclaveHTTPClient(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_ENCLAVE", "TINFOIL_REPO")
	c, err := NewEnclaveHTTPClient(context.Background(), os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO"), &EnclaveOptions{UserCacheSecret: "go-live-integration-cache-secret"})
	require.NoError(t, err)
	require.NotNil(t, c.Current(), "the client is verified when it's returned")
	before, err := c.EnsureVerified(context.Background())
	require.NoError(t, err)
	require.Equal(t, c.Current().Metadata().VerifiedAt, before.Metadata().VerifiedAt, "the constructor's verification is reused")
	after, err := c.Reverify(context.Background())
	require.NoError(t, err)
	require.False(t, after.Metadata().VerifiedAt.Before(before.Metadata().VerifiedAt))
}

func TestLiveVerificationCheck(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_ENCLAVE", "TINFOIL_REPO")
	rejection := errors.New("rejected by the test")
	// recorder returns a check that records the TLS key of each verification
	// it sees and rejects while reject says to.
	recorder := func(reject func(seen int) bool) (func(*verify.Verification) error, func() []string) {
		var mu sync.Mutex
		var keys []string
		check := func(v *verify.Verification) error {
			mu.Lock()
			defer mu.Unlock()
			key, _ := v.TLSPublicKeyFP()
			keys = append(keys, key)
			if reject(len(keys)) {
				return rejection
			}
			return nil
		}
		return check, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(keys)
		}
	}

	t.Run("discovery skips a rejected router", func(t *testing.T) {
		check, keys := recorder(func(seen int) bool { return seen == 1 })
		c, err := NewRouterHTTPClient(context.Background(), &EnclaveOptions{VerificationCheck: check})
		require.NoError(t, err)
		seen := keys()
		require.GreaterOrEqual(t, len(seen), 2)
		accepted, _ := c.Current().TLSPublicKeyFP()
		require.NotEqual(t, seen[0], accepted, "the rejected router isn't used")
		require.Equal(t, seen[len(seen)-1], accepted)
	})

	t.Run("an explicit enclave is rejected once", func(t *testing.T) {
		check, keys := recorder(func(int) bool { return true })
		c, err := NewEnclaveHTTPClient(context.Background(), os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO"), &EnclaveOptions{VerificationCheck: check})
		require.Nil(t, c, "a rejected enclave fails the constructor")
		require.ErrorIs(t, err, rejection)
		var attestation *AttestationError
		require.ErrorAs(t, err, &attestation)
		require.Len(t, keys(), 1, "a rejection isn't retried")
	})

	// replicatedCatalog fetches Tinfoil's gateway catalog once and returns it
	// with its model that has the most replicas. Clients built on that catalog
	// choose the model and verify it against the same snapshot.
	replicatedCatalog := func(t *testing.T) (Catalog, string) {
		base, err := url.Parse(defaultGatewayURL)
		require.NoError(t, err)
		catalog, err := FetchCatalog(context.Background(), base.Host)
		require.NoError(t, err)
		var model string
		for m, entry := range catalog {
			if len(entry.Hosts) > len(catalog[model].Hosts) {
				model = m
			}
		}
		require.GreaterOrEqual(t, len(catalog[model].Hosts), 2, "the gateway's catalog needs a model with two replicas")
		return catalog, model
	}

	t.Run("the gateway skips a rejected replica", func(t *testing.T) {
		check, keys := recorder(func(seen int) bool { return seen == 1 })
		catalog, model := replicatedCatalog(t)
		gw, err := NewGatewayHTTPClient(context.Background(), &GatewayOptions{Catalog: func() Catalog { return catalog }, VerificationCheck: check})
		require.NoError(t, err)
		verified, err := gw.EnsureVerified(context.Background(), model)
		require.NoError(t, err)
		seen := keys()
		require.GreaterOrEqual(t, len(seen), 2)
		accepted, _ := verified.TLSPublicKeyFP()
		require.NotEqual(t, seen[0], accepted, "the rejected replica isn't used")
		require.Equal(t, seen[len(seen)-1], accepted)
	})

	t.Run("the gateway checks each replica once", func(t *testing.T) {
		check, keys := recorder(func(int) bool { return true })
		catalog, model := replicatedCatalog(t)
		gw, err := NewGatewayHTTPClient(context.Background(), &GatewayOptions{Catalog: func() Catalog { return catalog }, VerificationCheck: check})
		require.NoError(t, err)
		_, err = gw.EnsureVerified(context.Background(), model)
		require.ErrorIs(t, err, rejection)
		seen := keys()
		require.GreaterOrEqual(t, len(seen), 2, "every replica is tried")
		distinct := map[string]bool{}
		for _, key := range seen {
			distinct[key] = true
		}
		require.Len(t, distinct, len(seen), "a rejected replica isn't retried")
		require.Empty(t, gw.Current(), "no rejected replica is kept")
	})
}

func TestValidateBaseURL(t *testing.T) {
	for _, baseURL := range []string{
		"https://proxy.example/v1/",
		"http://localhost:8080/v1/",
		"http://LOCALHOST/v1/",
		"http://127.0.0.1:8080/v1/",
		"http://127.1.2.3/v1/",
		"http://[::1]:8080/v1/",
	} {
		require.NoError(t, validateBaseURL(baseURL), baseURL)
	}
	for _, baseURL := range []string{
		"http://proxy.example/v1/",
		"http://app.localhost/v1/",
		"http://localhost.example/v1/",
		"http://0.0.0.0:8080/v1/",
		"http://10.0.0.1/v1/",
		"/v1/",
		"ftp://localhost/v1/",
	} {
		var config *ConfigurationError
		require.ErrorAs(t, validateBaseURL(baseURL), &config, baseURL)
	}
}

func TestLoopbackProxyAuthorizesOnlyItsOrigin(t *testing.T) {
	c, err := unverifiedEnclaveHTTPClient("enclave.example", "org/repo", &EnclaveOptions{TransportMode: TransportModeEHBP, BaseURL: "http://localhost:8080/v1/"})
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8080/v1/", c.BaseURL())
	for _, target := range []string{
		"https://localhost:8080/v1/models",
		"http://localhost:8081/v1/models",
		"http://127.0.0.1:8080/v1/models",
		"http://enclave.example/v1/models",
	} {
		_, err := c.Get(target)
		var config *ConfigurationError
		require.ErrorAs(t, err, &config, "%s is refused before verifying, so no network I/O", target)
		require.ErrorContains(t, err, "refusing to send request")
	}
}

func TestValidateTLSBaseURL(t *testing.T) {
	require.NoError(t, validateTLSBaseURL("", "enclave.example.com"))
	require.NoError(t, validateTLSBaseURL("https://enclave.example.com/custom/v1", "enclave.example.com"))
	require.NoError(t, validateTLSBaseURL("https://enclave.example.com:443/custom/v1", "enclave.example.com"))

	err := validateTLSBaseURL("https://proxy.example.com/v1", "enclave.example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "verified enclave origin")

	err = validateTLSBaseURL("http://enclave.example.com/v1", "enclave.example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "verified enclave origin")
}

// testKeyRejection is a key rejection as transport.IsKeyRejection reports one.
type testKeyRejection struct{ error }

func (testKeyRejection) KeyRejected() bool { return true }

func TestEnclaveChainStacksEveryLayer(t *testing.T) {
	var attempts []*http.Request
	var bodies []map[string]any
	conn := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
		req.Body.Close()
		attempts, bodies = append(attempts, req), append(bodies, body)
		if len(attempts) == 1 {
			return nil, testKeyRejection{errors.New("rotated key")}
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})
	rt, err := enclaveChain(conn, "enclave.example", "https://proxy.example/v1/", "cache-secret")
	require.NoError(t, err)

	// A body that can't be read twice: only the cache-secret layer, above the
	// replay, makes it replayable.
	req, err := http.NewRequest(http.MethodPost, "https://proxy.example/v1/chat/completions", io.NopCloser(strings.NewReader(`{"model":"m"}`)))
	require.NoError(t, err)
	require.Nil(t, req.GetBody)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Len(t, attempts, 2, "a key rejection is replayed once")
	for i, attempt := range attempts {
		require.Equal(t, "https://enclave.example", attempt.Header.Get("X-Tinfoil-Enclave-Url"), "every attempt names the enclave to the proxy")
		require.Equal(t, "cache-secret", bodies[i]["user_cache_secret"], "every attempt carries the cache secret")
	}

	req, err = http.NewRequest(http.MethodGet, "https://elsewhere.example/v1/models", nil)
	require.NoError(t, err)
	_, err = rt.RoundTrip(req)
	var config *ConfigurationError
	require.ErrorAs(t, err, &config, "origins other than the enclave and the base URL are refused")
	require.Len(t, attempts, 2)
}

func TestEnclaveHTTPClientRefusesOtherOrigins(t *testing.T) {
	for _, mode := range []TransportMode{TransportModeTLS, TransportModeEHBP} {
		c, err := unverifiedEnclaveHTTPClient("enclave.example", "org/repo", &EnclaveOptions{TransportMode: mode})
		require.NoError(t, err)
		_, err = c.Get("https://elsewhere.example/v1/models")
		var config *ConfigurationError
		require.ErrorAs(t, err, &config, "refused before verifying, so no network I/O")
		require.ErrorContains(t, err, "refusing to send request")
	}
}

func TestGatewayHTTPClientRefusesOtherOrigins(t *testing.T) {
	gw, err := NewGatewayHTTPClient(t.Context(), &GatewayOptions{Catalog: func() Catalog { return Catalog{} }})
	require.NoError(t, err)
	_, err = gw.Get("https://elsewhere.example/v1/models")
	var config *ConfigurationError
	require.ErrorAs(t, err, &config)
	require.ErrorContains(t, err, "refusing to send request")
}
