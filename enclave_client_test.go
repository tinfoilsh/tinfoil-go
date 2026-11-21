package tinfoil

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"testing/synctest"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

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
		host  string
		trust Trust
		opts  *EnclaveOptions
	}{
		"no host":                         {"", RepoPin{Repo: "org/repo"}, nil},
		"pointer to a transport":          {"enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: &EHBP{}}},
		"type that embeds a transport":    {"enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: embeddedTLS{}}},
		"plaintext remote proxy":          {"enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{ProxyURL: "http://proxy.example/v1/"}}},
		"relative proxy URL":              {"enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{ProxyURL: "/v1/"}}},
		"proxy on the enclave's origin":   {"enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{ProxyURL: "https://enclave.example/v1/"}}},
		"proxy on the enclave's port 443": {"enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{ProxyURL: "https://ENCLAVE.example:443/custom/v1/"}}},
		"invalid repository":              {"enclave.example", RepoPin{Repo: "not a reference"}, nil},
		"invalid project":                 {"enclave.example", ProjectPin{Project: "not a reference"}, nil},
		"invalid policy":                  {"enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Policy: verify.Policy{FreshnessMaxAge: -1}}},
		"invalid trust":                   {"enclave.example", AuthorizedBy{}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewEnclaveHTTPClient(t.Context(), tc.host, tc.trust, tc.opts)
			require.Nil(t, c)
			require.ErrorIs(t, err, ErrConfiguration)
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

		enclaveClient, err := NewEnclaveHTTPClient(context.Background(), "enclave.example", RepoPin{Repo: "org/repo"}, nil)
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

// emptyHome points HOME at an empty directory, where earlier versions
// persisted a generated cache secret, and returns that directory. It clears
// the environment variable that earlier versions read first, so that such a
// version would reach the file.
func emptyHome(t *testing.T) string {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TINFOIL_USER_CACHE_SECRET", "")
	return home
}

// requireEmptyDir fails unless dir is still empty.
func requireEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries, "no cache-secret file is written")
}

func TestNewEnclaveHTTPClientResolvesNoCacheSecret(t *testing.T) {
	home := emptyHome(t)
	_, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
	require.NoError(t, err)
	requireEmptyDir(t, home)
}

// The enclave client's chain has no cache secret, so it sends a body as it is,
// including a user_cache_secret that the caller set.
func TestEnclaveChainWithoutSecretLeavesBodiesAlone(t *testing.T) {
	var got []string
	conn := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		got = append(got, string(body))
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})
	rt, err := enclaveChain(conn, "enclave.example", "", "")
	require.NoError(t, err)
	for _, body := range []string{`{"model":"m"}`, `{"model":"m","user_cache_secret":"end-user"}`} {
		req, err := http.NewRequest(http.MethodPost, "https://enclave.example/v1/chat/completions", strings.NewReader(body))
		require.NoError(t, err)
		resp, err := rt.RoundTrip(req)
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.Equal(t, []string{`{"model":"m"}`, `{"model":"m","user_cache_secret":"end-user"}`}, got)
}

// The client's chain ends with the backstop, which classifies a response
// body that fails to read.
func TestEnclaveChainClassifiesAResponseBodyReadFailure(t *testing.T) {
	reset := errors.New("connection reset by peer")
	conn := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := io.MultiReader(strings.NewReader(`{"partial"`), iotest.ErrReader(reset))
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(body), Request: req}, nil
	})
	rt, err := enclaveChain(conn, "enclave.example", "", "")
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodGet, "https://enclave.example/v1/models", nil)
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	_, err = io.ReadAll(resp.Body)
	testutil.RequireCategory(t, err, ErrNetwork)
	require.ErrorIs(t, err, reset)
}

// The gateway client's chain ends with the backstop too, which classifies a
// request body that fails to read.
func TestGatewayHTTPClientClassifiesARequestBodyReadFailure(t *testing.T) {
	reset := errors.New("connection reset by peer")
	gw, err := unverifiedGatewayHTTPClient(&GatewayOptions{Catalog: func() Catalog { return Catalog{} }})
	require.NoError(t, err)
	_, err = gw.Post(defaultGatewayURL+"chat/completions", "application/json", iotest.ErrReader(reset))
	testutil.RequireCategory(t, err, ErrNetwork)
	require.ErrorIs(t, err, reset)
}

func TestEnclaveHTTPClientReportsItsEnclaveAndTrust(t *testing.T) {
	repo := "org/repo@v1@sha256:" + strings.Repeat("a", 64)
	c, err := unverifiedEnclaveHTTPClient("enclave.example:8443", RepoPin{Repo: repo}, &EnclaveOptions{Transport: EHBP{ProxyURL: "https://proxy.example/v1/"}})
	require.NoError(t, err)
	require.Equal(t, "enclave.example:8443", c.Enclave(), "the enclave, not the proxy")
	require.Equal(t, RepoPin{Repo: repo}, c.Trust(), "with its trust")

	ids := []string{verify.PublicRegistryID}
	scoped, err := unverifiedEnclaveHTTPClient("enclave.example", ProjectPin{Project: "org/project", RegistryIDs: ids}, nil)
	require.NoError(t, err)
	ids[0] = "changed"
	got := scoped.Trust().(ProjectPin)
	require.Equal(t, []string{verify.PublicRegistryID}, got.RegistryIDs, "the client copies the trust argument")
	got.RegistryIDs[0] = "changed"
	require.Equal(t, []string{verify.PublicRegistryID}, scoped.Trust().(ProjectPin).RegistryIDs, "and returns copies of it")

	authorized, err := unverifiedEnclaveHTTPClient("enclave.example", AuthorizedBy{Authorize: func(collateral.ConfigEndorsement) error { return nil }}, nil)
	require.NoError(t, err)
	require.IsType(t, AuthorizedBy{}, authorized.Trust())
}

// embeddedTLS embeds a variant, so it has the variant's methods without being
// one.
type embeddedTLS struct{ TLS }

func TestTransportDefaultsToTLS(t *testing.T) {
	for _, tc := range []struct {
		transport Transport
		want      Transport
	}{
		{nil, TLS{}},
		{TLS{}, TLS{}},
		{EHBP{}, EHBP{}},
		{EHBP{ProxyURL: "https://proxy.example/v1/"}, EHBP{ProxyURL: "https://proxy.example/v1/"}},
	} {
		got, err := resolveTransport(tc.transport)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
	}
	for _, invalid := range []Transport{&TLS{}, &EHBP{}, embeddedTLS{}} {
		_, err := resolveTransport(invalid)
		require.ErrorIs(t, err, ErrConfiguration, "%T", invalid)
	}
}

func TestKeyedTransportFollowsTheTransport(t *testing.T) {
	e := enclave.NewForTest("enclave.example", func() (*verify.Verification, error) {
		t.Error("each transport refuses its request before verifying")
		return nil, errors.New("unreachable")
	})
	upgrade, err := http.NewRequest(http.MethodGet, "https://enclave.example/v1/realtime", nil)
	require.NoError(t, err)
	upgrade.Header.Set("Upgrade", "websocket")
	plaintext, err := http.NewRequest(http.MethodGet, "http://enclave.example/v1/models", nil)
	require.NoError(t, err)
	_, err = keyedTransport(EHBP{}, e).RoundTrip(upgrade)
	require.ErrorContains(t, err, "EHBP seals only request and response bodies")
	_, err = keyedTransport(TLS{}, e).RoundTrip(plaintext)
	require.ErrorContains(t, err, "requires an HTTPS request")
}

func TestEnclaveHTTPClientUsesItsTransport(t *testing.T) {
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
		sealed, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{}})
		require.NoError(t, err)
		_, err = sealed.Do(upgrade())
		require.ErrorContains(t, err, "EHBP seals only request and response bodies")
		require.Zero(t, fetches, "EHBP refuses an upgrade before verifying")

		pinned, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
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
		"invalid policy":           {Policy: verify.Policy{FreshnessMaxAge: -1}, Catalog: catalog},
		"invalid pin policy":       {ModelPins: map[string]ModelPin{"m": {Repo: "tinfoilsh/m", Policy: &verify.Policy{FreshnessMaxAge: -1}}}, Catalog: catalog},
	} {
		t.Run(name, func(t *testing.T) {
			gw, err := NewGatewayHTTPClient(t.Context(), opts)
			require.Nil(t, gw)
			require.ErrorIs(t, err, ErrConfiguration)
		})
	}
}

func TestLiveRouterClient(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	apiKey := os.Getenv("TINFOIL_API_KEY")
	for name, tr := range map[string]Transport{"ehbp": EHBP{}, "tls": TLS{}} {
		t.Run(name, func(t *testing.T) {
			c, err := NewRouterHTTPClient(context.Background(), &RouterOptions{Transport: tr, UserCacheSecret: "go-live-integration-cache-secret"})
			require.NoError(t, err)
			oc, err := NewOpenAIClient(c, nil, option.WithAPIKey(apiKey))
			require.NoError(t, err)
			verified, err := c.EnsureVerified(context.Background())
			require.NoError(t, err)
			require.Equal(t, verified.FreshnessExpiresAt(), c.Current().FreshnessExpiresAt(), "a valid verification is reused")
			require.Equal(t, "https://"+c.Enclave()+"/", c.BaseURL(), "Enclave is the router discovery chose")
			require.Equal(t, "tinfoilsh/confidential-model-router", verified.ConfigRepo(), "the router is verified under Tinfoil's router repository")

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
	c, err := NewEnclaveHTTPClient(context.Background(), os.Getenv("TINFOIL_ENCLAVE"), RepoPin{Repo: os.Getenv("TINFOIL_REPO")}, nil)
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
		c, err := NewRouterHTTPClient(context.Background(), &RouterOptions{VerificationCheck: check})
		require.NoError(t, err)
		seen := keys()
		require.GreaterOrEqual(t, len(seen), 2)
		accepted, _ := c.Current().TLSPublicKeyFP()
		require.NotEqual(t, seen[0], accepted, "the rejected router isn't used")
		require.Equal(t, seen[len(seen)-1], accepted)
	})

	t.Run("an explicit enclave is rejected once", func(t *testing.T) {
		check, keys := recorder(func(int) bool { return true })
		c, err := NewEnclaveHTTPClient(context.Background(), os.Getenv("TINFOIL_ENCLAVE"), RepoPin{Repo: os.Getenv("TINFOIL_REPO")}, &EnclaveOptions{VerificationCheck: check})
		require.Nil(t, c, "a rejected enclave fails the constructor")
		require.ErrorIs(t, err, rejection)
		require.ErrorIs(t, err, ErrAttestation)
		require.Len(t, keys(), 1, "a rejection isn't retried")
	})

	// replicatedCatalog fetches Tinfoil's gateway catalog once and returns it
	// with its model that has the most replicas. Clients built on that catalog
	// choose the model and verify it against the same snapshot. It skips the
	// test when no model has two replicas, which depends on production capacity
	// rather than on the SDK.
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
		if len(catalog[model].Hosts) < 2 {
			t.Skipf("the gateway's catalog has no model with two replicas (the most is %d, for %q)", len(catalog[model].Hosts), model)
		}
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

func TestValidateProxyURL(t *testing.T) {
	for _, proxyURL := range []string{
		"https://proxy.example/v1/",
		"http://localhost:8080/v1/",
		"http://LOCALHOST/v1/",
		"http://127.0.0.1:8080/v1/",
		"http://127.1.2.3/v1/",
		"http://[::1]:8080/v1/",
	} {
		require.NoError(t, validateProxyURL(proxyURL), proxyURL)
	}
	for _, proxyURL := range []string{
		"http://proxy.example/v1/",
		"http://app.localhost/v1/",
		"http://localhost.example/v1/",
		"http://0.0.0.0:8080/v1/",
		"http://10.0.0.1/v1/",
		"/v1/",
		"ftp://localhost/v1/",
	} {
		require.ErrorIs(t, validateProxyURL(proxyURL), ErrConfiguration, proxyURL)
	}
}

// refusedURLParts are URLs with user information, a query or a fragment, each
// of which every option that takes a proxy or base URL refuses.
var refusedURLParts = map[string]string{
	"user information":          "https://user:secret@proxy.example/v1/",
	"user with empty password":  "https://user:@proxy.example/v1/",
	"user without password":     "https://user@proxy.example/v1/",
	"empty user information":    "https://@proxy.example/v1/",
	"query":                     "https://proxy.example/v1/?a=1",
	"empty query":               "https://proxy.example/v1/?",
	"fragment":                  "https://proxy.example/v1/#x",
	"empty fragment":            "https://proxy.example/v1/#",
	"loopback HTTP with a user": "http://user:secret@localhost:8080/v1/",
	"loopback HTTP with query":  "http://localhost:8080/v1/?a=1",
}

func TestURLOptionsRefuseUserInfoQueryAndFragment(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Errorf("a refused base URL sent %s %s", req.Method, req.URL)
		return nil, errors.New("no network in this test")
	})
	requireRefused := func(t *testing.T, err error, prefix string) {
		t.Helper()
		require.ErrorIs(t, err, ErrConfiguration)
		require.ErrorContains(t, err, prefix)
		require.NotContains(t, err.Error(), "secret", "the error doesn't echo the credentials")
	}
	for name, rawURL := range refusedURLParts {
		t.Run(name, func(t *testing.T) {
			requireRefused(t, validateProxyURL(rawURL), "invalid proxy URL:")
			c, err := NewEnclaveHTTPClient(t.Context(), "enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{ProxyURL: rawURL}})
			require.Nil(t, c)
			requireRefused(t, err, "invalid proxy URL:")
			r, err := NewRouterHTTPClient(t.Context(), &RouterOptions{Transport: EHBP{ProxyURL: rawURL}})
			require.Nil(t, r)
			requireRefused(t, err, "invalid proxy URL:")
			gw, err := NewGatewayHTTPClient(t.Context(), &GatewayOptions{URL: rawURL, Catalog: func() Catalog { return Catalog{} }})
			require.Nil(t, gw)
			requireRefused(t, err, "invalid base URL:")
		})
	}
}

func TestURLOptionsWithAPathAreAccepted(t *testing.T) {
	for _, proxyURL := range []string{"https://proxy.example/custom/", "http://localhost:8080/custom/"} {
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{ProxyURL: proxyURL}})
		require.NoError(t, err, proxyURL)
		require.Equal(t, proxyURL, c.BaseURL())
		oc, err := NewOpenAIClient(c, nil)
		require.NoError(t, err)
		require.Equal(t, proxyURL+"v1/", oc.BaseURL(), "OpenAI clients send to v1/ under the proxy URL")
	}
	gw, err := unverifiedGatewayHTTPClient(&GatewayOptions{URL: "https://gateway.example/custom/v1/", Catalog: func() Catalog { return Catalog{} }})
	require.NoError(t, err)
	require.Equal(t, "https://gateway.example/custom/v1/", gw.BaseURL())
}

func TestDirectTransportsSendToTheEnclaveOrigin(t *testing.T) {
	for _, tr := range []Transport{nil, TLS{}, EHBP{}} {
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: tr})
		require.NoError(t, err)
		require.Equal(t, "https://enclave.example/", c.BaseURL(), "%T", tr)
		oc, err := NewOpenAIClient(c, nil)
		require.NoError(t, err)
		require.Equal(t, "https://enclave.example/v1/", oc.BaseURL(), "%T", tr)
	}
}

func TestLoopbackProxyAuthorizesOnlyItsOrigin(t *testing.T) {
	c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{ProxyURL: "http://localhost:8080/v1/"}})
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8080/v1/", c.BaseURL())
	for _, target := range []string{
		"https://localhost:8080/v1/models",
		"http://localhost:8081/v1/models",
		"http://127.0.0.1:8080/v1/models",
		"http://enclave.example/v1/models",
	} {
		_, err := c.Get(target)
		require.ErrorIs(t, err, ErrConfiguration, "%s is refused before verifying, so no network I/O", target)
		require.ErrorContains(t, err, "refusing to send request")
	}
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
	require.ErrorIs(t, err, ErrConfiguration, "origins other than the enclave and the base URL are refused")
	require.Len(t, attempts, 2)
}

func TestEnclaveHTTPClientRefusesOtherOrigins(t *testing.T) {
	for _, tr := range []Transport{TLS{}, EHBP{}, EHBP{ProxyURL: "https://proxy.example/v1/"}} {
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: tr})
		require.NoError(t, err)
		_, err = c.Get("https://elsewhere.example/v1/models")
		require.ErrorIs(t, err, ErrConfiguration, "refused before verifying, so no network I/O")
		require.ErrorContains(t, err, "refusing to send request")
	}
}

func TestGatewayHTTPClientRefusesOtherOrigins(t *testing.T) {
	gw, err := NewGatewayHTTPClient(t.Context(), &GatewayOptions{Catalog: func() Catalog { return Catalog{} }})
	require.NoError(t, err)
	_, err = gw.Get("https://elsewhere.example/v1/models")
	require.ErrorIs(t, err, ErrConfiguration)
	require.ErrorContains(t, err, "refusing to send request")
}
