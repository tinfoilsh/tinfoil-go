package tinfoil

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

func TestNewEnclaveClientRejectsInvalidOptions(t *testing.T) {
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
			c, err := NewEnclaveClient(tc.host, tc.repo, tc.opts)
			require.Nil(t, c)
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
		})
	}
}

func TestDiscoverRouterRejectsInvalidOptionsBeforeDiscovery(t *testing.T) {
	for _, opts := range []*EnclaveOptions{{Binding: "quic"}, {BaseURL: "http://proxy.example/v1/"}} {
		c, err := DiscoverRouter(context.Background(), opts)
		require.Nil(t, c)
		var config *ConfigurationError
		require.ErrorAs(t, err, &config)
	}
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

func TestGatewayClientServesPinnedModels(t *testing.T) {
	catalog := Catalog{
		"pinned":   {Repo: "tinfoilsh/pinned", Hosts: []string{"a.example"}},
		"unpinned": {Repo: "tinfoilsh/unpinned", Hosts: []string{"b.example"}},
	}
	gw, err := NewGatewayClient(&GatewayOptions{
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

func TestNewGatewayClientRejectsInvalidOptions(t *testing.T) {
	catalog := func() Catalog { return Catalog{} }
	for name, opts := range map[string]*GatewayOptions{
		"plaintext URL":            {URL: "http://gateway.example/v1/", Catalog: catalog},
		"pinned-only without pins": {PinnedModelsOnly: true, Catalog: catalog},
		"pin outside tinfoilsh":    {ModelPins: map[string]ModelPin{"m": {Repo: "acme/m"}}, Catalog: catalog},
		"invalid pin reference":    {ModelPins: map[string]ModelPin{"m": {Repo: "tinfoilsh/m@"}}, Catalog: catalog},
	} {
		t.Run(name, func(t *testing.T) {
			gw, err := NewGatewayClient(opts)
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
			c, err := DiscoverRouter(context.Background(), &EnclaveOptions{Binding: binding, UserCacheSecret: "go-live-integration-cache-secret"})
			require.NoError(t, err)
			verified, err := c.EnsureVerified(context.Background())
			require.NoError(t, err)
			require.Equal(t, verified.FreshnessExpiresAt(), c.Current().FreshnessExpiresAt(), "a valid verification is reused")

			completion, err := c.OpenAI(option.WithAPIKey(apiKey)).Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
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

func TestLiveNewEnclaveClient(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_ENCLAVE", "TINFOIL_REPO")
	c, err := NewEnclaveClient(os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO"), &EnclaveOptions{UserCacheSecret: "go-live-integration-cache-secret"})
	require.NoError(t, err)
	before := c.Current()
	require.NotNil(t, before, "the client verifies at construction")
	after, err := c.Reverify(context.Background())
	require.NoError(t, err)
	require.False(t, after.Metadata().VerifiedAt.Before(before.Metadata().VerifiedAt))
}
