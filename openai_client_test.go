package tinfoil

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
)

type recordingTransport struct{ urls []string }

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.urls = append(r.urls, req.URL.String())
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"object":"list","data":[]}`)),
		Request:    req,
	}, nil
}

// openAIClientCase builds an OpenAI client of one kind over an HTTP client
// whose default OpenAI base URL is wantDefault.
type openAIClientCase struct {
	name string
	// newClient returns the OpenAI client, the HTTP client it should send
	// through, and the plain client's embedded client.
	newClient   func(t *testing.T, opts ...option.RequestOption) (client *openai.Client, secure, embedded *http.Client, err error)
	wantDefault string
}

func openAIClientCases() []openAIClientCase {
	return []openAIClientCase{
		{
			name: "enclave",
			newClient: func(t *testing.T, opts ...option.RequestOption) (*openai.Client, *http.Client, *http.Client, error) {
				c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
				require.NoError(t, err)
				oc, err := newEnclaveOpenAIClient(c, opts)
				if err != nil {
					return nil, nil, nil, err
				}
				require.Same(t, c, oc.HTTPClient())
				return oc.Client, c.secure, c.Client, nil
			},
			wantDefault: "https://enclave.example/v1/",
		},
		{
			name: "router",
			newClient: func(t *testing.T, opts ...option.RequestOption) (*openai.Client, *http.Client, *http.Client, error) {
				c := &RouterHTTPClient{Client: &http.Client{}, attestedClient: attestedClient{secure: &http.Client{}, openAIURL: openAIURL("https://router.example")}}
				oc, err := newRouterOpenAIClient(c, opts)
				if err != nil {
					return nil, nil, nil, err
				}
				require.Same(t, c, oc.HTTPClient())
				return oc.Client, c.secure, c.Client, nil
			},
			wantDefault: "https://router.example/v1/",
		},
		{
			name: "gateway",
			newClient: func(t *testing.T, opts ...option.RequestOption) (*openai.Client, *http.Client, *http.Client, error) {
				oc, err := NewGatewayOpenAIClient(t.Context(), &GatewayOptions{
					URL:     "https://gateway.example/api/v1/",
					Catalog: func() Catalog { return Catalog{} },
				}, opts...)
				if err != nil {
					return nil, nil, nil, err
				}
				return oc.Client, oc.HTTPClient().secure, oc.HTTPClient().Client, nil
			},
			wantDefault: "https://gateway.example/api/v1/",
		},
	}
}

// listModels sends a request through client and returns the URLs that reached
// secure.
func listModels(t *testing.T, client *openai.Client, secure *http.Client) []string {
	t.Helper()
	rec := &recordingTransport{}
	secure.Transport = rec
	_, err := client.Models.List(context.Background())
	require.NoError(t, err)
	return rec.urls
}

func TestOpenAIClientsSendThroughTheirHTTPClient(t *testing.T) {
	for _, tc := range openAIClientCases() {
		t.Run(tc.name, func(t *testing.T) {
			caller, replaced := &recordingTransport{}, &recordingTransport{}
			client, secure, embedded, err := tc.newClient(t,
				option.WithHTTPClient(&http.Client{Transport: caller}),
				option.WithMaxRetries(0),
			)
			require.NoError(t, err)
			embedded.Transport = replaced

			require.Equal(t, []string{tc.wantDefault + "models"}, listModels(t, client, secure))
			require.Empty(t, caller.urls, "the caller's HTTP client is replaced")
			require.Empty(t, replaced.urls, "changing the embedded client doesn't reach the OpenAI client")
		})
	}
}

func TestOpenAIClientsIgnoreTheBaseURLEnvironmentVariable(t *testing.T) {
	t.Setenv("OPENAI_BASE_URL", "https://api.openai.com/v1/")
	for _, tc := range openAIClientCases() {
		t.Run(tc.name, func(t *testing.T) {
			client, secure, _, err := tc.newClient(t)
			require.NoError(t, err)
			require.Equal(t, []string{tc.wantDefault + "models"}, listModels(t, client, secure))
		})
	}
}

func TestOpenAIClientsHonorASameOriginBaseURL(t *testing.T) {
	for _, tc := range openAIClientCases() {
		t.Run(tc.name, func(t *testing.T) {
			override := strings.Replace(tc.wantDefault, "v1/", "custom/v2", 1)
			client, secure, _, err := tc.newClient(t, option.WithBaseURL(override))
			require.NoError(t, err)
			require.Equal(t, []string{override + "/models"}, listModels(t, client, secure))
		})
	}
}

func TestOpenAIClientsReadTheBaseURLWithoutRunningMiddleware(t *testing.T) {
	for _, tc := range openAIClientCases() {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			count := option.WithMiddleware(func(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
				calls++
				return next(req)
			})
			client, secure, _, err := tc.newClient(t, count, option.WithQuery("q", "1"))
			require.NoError(t, err)
			require.Zero(t, calls, "construction runs no caller middleware")
			require.Equal(t, []string{tc.wantDefault + "models?q=1"}, listModels(t, client, secure))
			require.Equal(t, 1, calls)
		})
	}
}

func TestOpenAIClientsRejectACrossOriginBaseURL(t *testing.T) {
	for _, tc := range openAIClientCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, override := range []string{
				"https://evil.example/v1/",
				strings.Replace(tc.wantDefault, "https://", "http://", 1),
				strings.Replace(tc.wantDefault, ".example/", ".example:8443/", 1),
				strings.Replace(tc.wantDefault, "https://", "https://user:secret@", 1),
				"/v1/",
			} {
				client, _, _, err := tc.newClient(t, option.WithBaseURL(override))
				require.Nil(t, client)
				require.ErrorIs(t, err, ErrConfiguration, override)
				require.NotContains(t, err.Error(), "secret")
			}
		})
	}
}

func TestOpenAIURLJoinsV1UnderItsBase(t *testing.T) {
	for base, want := range map[string]string{
		"https://enclave.example/":    "https://enclave.example/v1/",
		"https://proxy.example":       "https://proxy.example/v1/",
		"https://proxy.example/":      "https://proxy.example/v1/",
		"https://proxy.example/api":   "https://proxy.example/api/v1/",
		"https://proxy.example/api/":  "https://proxy.example/api/v1/",
		"http://localhost:8080/relay": "http://localhost:8080/relay/v1/",
	} {
		require.Equal(t, want, openAIURL(base), base)
	}
}

func TestOpenAIClientsDefaultUnderTheProxy(t *testing.T) {
	for _, proxyURL := range []string{"https://proxy.example/relay", "https://proxy.example/relay/"} {
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: EHBP{ProxyURL: proxyURL}})
		require.NoError(t, err)
		oc, err := newEnclaveOpenAIClient(c, nil)
		require.NoError(t, err)
		require.Equal(t, []string{"https://proxy.example/relay/v1/models"}, listModels(t, oc.Client, c.secure), proxyURL)
		require.Equal(t, proxyURL, c.BaseURL(), "the HTTP client still sends to the proxy URL itself")

		oc, err = newEnclaveOpenAIClient(c, []option.RequestOption{option.WithBaseURL("https://proxy.example/other/")})
		require.NoError(t, err)
		require.Equal(t, []string{"https://proxy.example/other/models"}, listModels(t, oc.Client, c.secure))

		_, err = newEnclaveOpenAIClient(c, []option.RequestOption{option.WithBaseURL("https://enclave.example/v1/")})
		require.ErrorIs(t, err, ErrConfiguration, "a proxied client's base URL stays on the proxy")
	}
}

func TestOpenAIClientsCheckTheBaseURLBeforeNetworkIO(t *testing.T) {
	// A done context makes verification, discovery and the catalog fetch
	// fail, so only a check made before them reports ErrConfiguration.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	evil := option.WithBaseURL("https://evil.example/v1/")
	pin := RepoPin{Repo: "org/repo"}
	proxied := &EnclaveOptions{Transport: EHBP{ProxyURL: "https://proxy.example/"}}
	routerProxied := &RouterOptions{Transport: EHBP{ProxyURL: "https://proxy.example/"}}
	gateway := &GatewayOptions{URL: "https://gateway.example/v1/", Catalog: func() Catalog { return Catalog{} }}

	_, err := NewEnclaveOpenAIClient(ctx, "enclave.example", pin, nil, evil)
	require.ErrorIs(t, err, ErrConfiguration)
	_, err = NewEnclaveOpenAIClient(ctx, "enclave.example", pin, proxied, option.WithBaseURL("https://enclave.example/v1/"))
	require.ErrorIs(t, err, ErrConfiguration)
	_, err = NewRouterOpenAIClient(ctx, routerProxied, evil)
	require.ErrorIs(t, err, ErrConfiguration)
	_, err = NewGatewayOpenAIClient(ctx, gateway, evil)
	require.ErrorIs(t, err, ErrConfiguration)
	// A router client without a proxy learns its origin only from discovery,
	// but an option that can't apply still fails first.
	_, err = NewRouterOpenAIClient(ctx, nil, option.WithBaseURL("https://user:secret@router.example/"))
	require.ErrorIs(t, err, ErrConfiguration)

	_, err = NewEnclaveOpenAIClient(ctx, "enclave.example", pin, nil, option.WithBaseURL("https://enclave.example/v2/"))
	require.ErrorIs(t, err, context.Canceled, "a same-origin base URL reaches verification")
	_, err = NewEnclaveOpenAIClient(ctx, "enclave.example", pin, proxied, option.WithBaseURL("https://proxy.example/v2/"))
	require.ErrorIs(t, err, context.Canceled, "a base URL on the proxy reaches verification")
	_, err = NewRouterOpenAIClient(ctx, routerProxied, option.WithBaseURL("https://proxy.example/v2/"))
	require.ErrorIs(t, err, context.Canceled, "a base URL on the proxy reaches discovery")
	_, err = NewGatewayOpenAIClient(ctx, gateway, option.WithBaseURL("https://gateway.example/v2/"))
	require.ErrorIs(t, err, context.Canceled, "a base URL on the gateway reaches the catalog fetch")
}

func TestOpenAIClientsRejectInvalidOptions(t *testing.T) {
	enclave, err := NewEnclaveOpenAIClient(t.Context(), "", RepoPin{Repo: "org/repo"}, nil)
	require.Nil(t, enclave)
	require.ErrorIs(t, err, ErrConfiguration)
	router, err := NewRouterOpenAIClient(t.Context(), &RouterOptions{Transport: &TLS{}})
	require.Nil(t, router)
	require.ErrorIs(t, err, ErrConfiguration)
	gateway, err := NewGatewayOpenAIClient(t.Context(), &GatewayOptions{URL: "http://gateway.example/v1/", Catalog: func() Catalog { return Catalog{} }})
	require.Nil(t, gateway)
	require.ErrorIs(t, err, ErrConfiguration)
}
