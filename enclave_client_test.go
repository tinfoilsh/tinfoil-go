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
	for name, tc := range map[string]struct {
		host, repo string
		opts       *EnclaveOptions
	}{
		"no host":             {"", "org/repo", nil},
		"unknown binding":     {"enclave.example", "org/repo", &EnclaveOptions{Binding: "quic"}},
		"plaintext base URL":  {"enclave.example", "org/repo", &EnclaveOptions{BaseURL: "http://proxy.example/v1/"}},
		"relative base URL":   {"enclave.example", "org/repo", &EnclaveOptions{BaseURL: "/v1/"}},
		"TLS through a proxy": {"enclave.example", "org/repo", &EnclaveOptions{BaseURL: "https://proxy.example/v1/"}},
		"invalid repository":  {"enclave.example", "not a reference", nil},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewEnclaveHTTPClient(tc.host, tc.repo, tc.opts)
			require.Nil(t, c)
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
		})
	}
}

func TestDiscoverRouterRejectsInvalidOptionsBeforeDiscovery(t *testing.T) {
	// A done context makes discovery itself fail, so only a check made before
	// discovery reports a ConfigurationError.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, opts := range []*EnclaveOptions{
		{Binding: "quic"},
		{BaseURL: "http://proxy.example/v1/"},
		{Binding: BindingTLS, BaseURL: "https://proxy.example/v1/"},
		{Verifier: callerAuthorizedVerifier(t)},
	} {
		c, err := DiscoverRouter(ctx, opts)
		require.Nil(t, c)
		var config *ConfigurationError
		require.ErrorAs(t, err, &config)
	}
}

func TestDiscoverRouterVerifiesTheFallbackUnderItsContext(t *testing.T) {
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
			_, err := DiscoverRouter(ctx, nil)
			done <- err
		}()
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.DeadlineExceeded)
		case <-time.After(time.Minute):
			t.Fatal("DiscoverRouter kept verifying the fallback after its context expired")
		}
	})
}

func TestBindingDefaultsToTheRoutes(t *testing.T) {
	for _, tc := range []struct {
		binding      Binding
		routeDefault enclave.Binding
		want         enclave.Binding
	}{
		{"", enclave.TLS, enclave.TLS},
		{"", enclave.EHBP, enclave.EHBP},
		{BindingTLS, enclave.EHBP, enclave.TLS},
		{BindingEHBP, enclave.TLS, enclave.EHBP},
	} {
		got, err := tc.binding.enclaveBinding(tc.routeDefault)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
	}
}

func TestGatewayHTTPClientServesPinnedModels(t *testing.T) {
	catalog := Catalog{
		"pinned":   {Repo: "tinfoilsh/pinned", Hosts: []string{"a.example"}},
		"unpinned": {Repo: "tinfoilsh/unpinned", Hosts: []string{"b.example"}},
	}
	gw, err := NewGatewayHTTPClient(&GatewayOptions{
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
			gw, err := NewGatewayHTTPClient(opts)
			require.Nil(t, gw)
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
		})
	}
}

func TestLiveDiscoverRouter(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	apiKey := os.Getenv("TINFOIL_API_KEY")
	for _, binding := range []Binding{BindingEHBP, BindingTLS} {
		t.Run(string(binding), func(t *testing.T) {
			oc, err := DiscoverRouterOpenAI(context.Background(), &EnclaveOptions{Binding: binding, UserCacheSecret: "go-live-integration-cache-secret"}, option.WithAPIKey(apiKey))
			require.NoError(t, err)
			c := oc.HTTPClient()
			verified, err := c.EnsureVerified(context.Background())
			require.NoError(t, err)
			require.Equal(t, verified.FreshnessExpiresAt(), c.Current().FreshnessExpiresAt(), "a valid verification is reused")

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
	c, err := NewEnclaveHTTPClient(os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO"), &EnclaveOptions{UserCacheSecret: "go-live-integration-cache-secret"})
	require.NoError(t, err)
	before := c.Current()
	require.NotNil(t, before, "the client verifies at construction")
	after, err := c.Reverify(context.Background())
	require.NoError(t, err)
	require.False(t, after.Metadata().VerifiedAt.Before(before.Metadata().VerifiedAt))
}
