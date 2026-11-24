package tinfoil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
)

type recordingTransport struct{ urls, auths []string }

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.urls = append(r.urls, req.URL.String())
	r.auths = append(r.auths, req.Header.Get("Authorization"))
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"object":"list","data":[]}`)),
		Request:    req,
	}, nil
}

// attestedCase is an attested HTTP client of one kind, made without network
// I/O, and the base URL that an OpenAIClient over it defaults to.
type attestedCase struct {
	name        string
	newClient   func(t *testing.T) (hc AttestedHTTPClient, secure, embedded *http.Client)
	wantDefault string
}

func enclaveCase(name string, tr Transport, wantDefault string) attestedCase {
	return attestedCase{name: name, wantDefault: wantDefault, newClient: func(t *testing.T) (AttestedHTTPClient, *http.Client, *http.Client) {
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: tr})
		require.NoError(t, err)
		return c, c.secure, c.Client
	}}
}

func attestedCases() []attestedCase {
	return []attestedCase{
		enclaveCase("enclave", nil, "https://enclave.example/v1/"),
		enclaveCase("enclave through a proxy", EHBP{ProxyURL: "https://proxy.example/relay"}, "https://proxy.example/relay/v1/"),
		enclaveCase("enclave through a proxy with a trailing slash", EHBP{ProxyURL: "https://proxy.example/relay/"}, "https://proxy.example/relay/v1/"),
		{
			name: "router",
			newClient: func(t *testing.T) (AttestedHTTPClient, *http.Client, *http.Client) {
				c := &RouterHTTPClient{Client: &http.Client{}, attestedClient: attestedClient{secure: &http.Client{}, baseURL: "https://router.example/"}}
				return c, c.secure, c.Client
			},
			wantDefault: "https://router.example/v1/",
		},
		gatewayCase("gateway", "", "https://inference-gateway.tinfoil.sh/v1/"),
		gatewayCase("gateway at an origin", "https://gateway.example", "https://gateway.example/v1/"),
		gatewayCase("gateway under a path", "https://gateway.example/mount", "https://gateway.example/mount/v1/"),
		gatewayCase("gateway under a path with a trailing slash", "https://gateway.example/mount/", "https://gateway.example/mount/v1/"),
	}
}

func gatewayCase(name, gatewayURL, wantDefault string) attestedCase {
	return attestedCase{name: name, wantDefault: wantDefault, newClient: func(t *testing.T) (AttestedHTTPClient, *http.Client, *http.Client) {
		c, err := unverifiedGatewayHTTPClient(&GatewayOptions{ModelPins: testModelPins, URL: gatewayURL, Catalog: func() Catalog { return Catalog{} }})
		require.NoError(t, err)
		return c, c.secure, c.Client
	}}
}

// listModels sends a request through client and returns the URLs that reached
// secure.
func listModels(t *testing.T, client *OpenAIClient, secure *http.Client, opts ...option.RequestOption) []string {
	t.Helper()
	rec := &recordingTransport{}
	secure.Transport = rec
	_, err := client.Models.List(context.Background(), opts...)
	require.NoError(t, err)
	return rec.urls
}

func TestOpenAIClientSendsThroughItsHTTPClient(t *testing.T) {
	for _, tc := range attestedCases() {
		t.Run(tc.name, func(t *testing.T) {
			hc, secure, embedded := tc.newClient(t)
			caller, replaced := &recordingTransport{}, &recordingTransport{}
			client, err := NewOpenAIClient(hc,
				option.WithHTTPClient(&http.Client{Transport: caller}),
				option.WithMaxRetries(0),
			)
			require.NoError(t, err)
			require.Same(t, hc, client.HTTPClient())
			require.Equal(t, tc.wantDefault, client.BaseURL())
			embedded.Transport = replaced

			require.Equal(t, []string{tc.wantDefault + "models"}, listModels(t, client, secure))
			require.Empty(t, caller.urls, "the caller's HTTP client is replaced")
			require.Empty(t, replaced.urls, "changing the embedded client doesn't reach the OpenAI client")
		})
	}
}

func TestOpenAIClientIgnoresTheCallersBaseURL(t *testing.T) {
	t.Setenv("OPENAI_BASE_URL", "https://api.openai.com/v1/")
	for _, tc := range attestedCases() {
		t.Run(tc.name, func(t *testing.T) {
			hc, secure, _ := tc.newClient(t)
			for _, opt := range []option.RequestOption{
				option.WithBaseURL("https://evil.example/v1/"),
				option.WithBaseURL(strings.Replace(tc.wantDefault, "v1/", "other/", 1)),
				option.WithDataResidency(option.DataResidencyUS),
			} {
				client, err := NewOpenAIClient(hc, opt)
				require.NoError(t, err)
				require.Equal(t, []string{tc.wantDefault + "models"}, listModels(t, client, secure))
			}
		})
	}
}

func TestOpenAIClientKeepsTheCallersOtherOptions(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "from-the-environment")
	c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
	require.NoError(t, err)
	rec := &recordingTransport{}
	c.secure.Transport = rec

	client, err := NewOpenAIClient(c)
	require.NoError(t, err)
	_, err = client.Models.List(context.Background())
	require.NoError(t, err)
	client, err = NewOpenAIClient(c, option.WithAPIKey("from-the-caller"), option.WithQuery("q", "1"))
	require.NoError(t, err)
	_, err = client.Models.List(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"Bearer from-the-environment", "Bearer from-the-caller"}, rec.auths)
	require.Equal(t, "https://enclave.example/v1/models?q=1", rec.urls[1])
}

func TestOpenAIClientJoinsTheAPIPath(t *testing.T) {
	for _, tc := range []struct {
		tr      Transport
		apiPath string
		want    string
	}{
		{nil, "/", "https://enclave.example/"},
		{nil, "/v2", "https://enclave.example/v2/"},
		{nil, "/openai/v1/", "https://enclave.example/openai/v1/"},
		{EHBP{ProxyURL: "https://proxy.example"}, "/v2", "https://proxy.example/v2/"},
		{EHBP{ProxyURL: "https://proxy.example/relay"}, "/openai/v1", "https://proxy.example/relay/openai/v1/"},
		{EHBP{ProxyURL: "https://proxy.example/relay/"}, "/openai/v1/", "https://proxy.example/relay/openai/v1/"},
		{EHBP{ProxyURL: "http://localhost:8080"}, "", "http://localhost:8080/v1/"},
	} {
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, &EnclaveOptions{Transport: tc.tr})
		require.NoError(t, err)
		client, err := NewOpenAIClient(c, apiPathOptions(tc.apiPath)...)
		require.NoError(t, err, tc.apiPath)
		require.Equal(t, tc.want, client.BaseURL(), "%v %q", tc.tr, tc.apiPath)
		require.Equal(t, []string{tc.want + "models"}, listModels(t, client, c.secure))
	}
}

// apiPathOptions returns WithAPIPath(apiPath), or no option for an empty
// apiPath, which leaves the default.
func apiPathOptions(apiPath string) []option.RequestOption {
	if apiPath == "" {
		return nil
	}
	return []option.RequestOption{WithAPIPath(apiPath)}
}

func TestOpenAIClientRejectsAnInvalidAPIPath(t *testing.T) {
	c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
	require.NoError(t, err)
	for _, tc := range []struct {
		apiPath string
		reason  string
	}{
		{"", "absolute path"},
		{"v1", "absolute path"},
		{"v1/", "absolute path"},
		{"//evil.example/v1/", "absolute path"},
		{"https://evil.example/v1/", "absolute path"},
		{"/v1/?q=1", "query or a fragment"},
		{"/v1/#f", "query or a fragment"},
		{"/v1?", "query or a fragment"},
		{"/v1/../admin", "segment"},
		{"/..", "segment"},
		{"/./v1", "segment"},
		{"/%2e%2e/admin", "segment"},
		{"/v1/%2E/", "segment"},
		{"/a%2fb/", "encoded slash"},
		{"/a%2Fb/", "encoded slash"},
		{"/a%5cb/", "backslash"},
		{"/a%5C..%5Cb/", "backslash"},
		{"/%zz/", "invalid URL escape"},
		{"/v1/%", "invalid URL escape"},
		{"/v1/%2", "invalid URL escape"},
		{"/v1\\..\\admin/", "RFC 3986"},
		{"/v1 /", "RFC 3986"},
		{"/v1\n/", "RFC 3986"},
		{"/v\t1/", "RFC 3986"},
		{"/v1\r/", "RFC 3986"},
		{"/v1\x00/", "RFC 3986"},
		{"/v1\x7f/", "RFC 3986"},
		{"/v1/\u00a0/", "RFC 3986"},
		{"/v1/\u2028/", "RFC 3986"},
		{"/v1/\u00e9/", "RFC 3986"},
		{`/v1/"/`, "RFC 3986"},
		{"/v1/</", "RFC 3986"},
		{"/v1/>/", "RFC 3986"},
		{"/v1/[/", "RFC 3986"},
		{"/v1/]/", "RFC 3986"},
		{"/v1/^/", "RFC 3986"},
		{"/v1/`/", "RFC 3986"},
		{"/v1/{/", "RFC 3986"},
		{"/v1/|/", "RFC 3986"},
		{"/v1/}/", "RFC 3986"},
	} {
		client, err := NewOpenAIClient(c, WithAPIPath(tc.apiPath))
		require.Nil(t, client, "%q", tc.apiPath)
		require.ErrorIs(t, err, ErrConfiguration, "%q", tc.apiPath)
		require.ErrorContains(t, err, tc.reason, "%q", tc.apiPath)
	}
}

func TestOpenAIClientAcceptsEveryRFC3986PathCharacter(t *testing.T) {
	c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
	require.NoError(t, err)
	for _, apiPath := range []string{
		"/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/0123456789/",
		"/-._~/",
		"/!$&'()*+,;=/",
		"/:@/",
		"/v%31/",
		"/a%20b/",
		"/%c3%a9/",
		"/%ff/",
		"/%2e%2e%2e/",
		"/.well-known/",
		"/.../",
	} {
		client, err := NewOpenAIClient(c, WithAPIPath(apiPath))
		require.NoError(t, err, "%q", apiPath)
		require.Equal(t, "https://enclave.example"+apiPath, client.BaseURL())
	}
}

func TestOpenAIClientAcceptsOnlyRFC3986PathCharacters(t *testing.T) {
	const pathChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/"
	for b := 0; b < 256; b++ {
		apiPath := "/a" + string([]byte{byte(b)}) + "b/"
		err := validateAPIPath(apiPath)
		if strings.IndexByte(pathChars, byte(b)) >= 0 {
			require.NoError(t, err, "%q", apiPath)
		} else {
			require.ErrorIs(t, err, ErrConfiguration, "%q", apiPath)
		}
	}
}

func TestOpenAIClientJoinsTheAPIPathUnderTheGatewayURL(t *testing.T) {
	for _, tc := range []struct {
		gatewayURL, apiPath, want string
	}{
		{"", "", "https://inference-gateway.tinfoil.sh/v1/"},
		{"", "/openai/v1", "https://inference-gateway.tinfoil.sh/openai/v1/"},
		{"https://gateway.example", "/v2", "https://gateway.example/v2/"},
		{"https://gateway.example/mount", "/openai/v1", "https://gateway.example/mount/openai/v1/"},
		{"https://gateway.example/mount/", "/openai/v1/", "https://gateway.example/mount/openai/v1/"},
	} {
		gw, err := unverifiedGatewayHTTPClient(&GatewayOptions{ModelPins: testModelPins, URL: tc.gatewayURL, Catalog: func() Catalog { return Catalog{} }})
		require.NoError(t, err)
		client, err := NewOpenAIClient(gw, apiPathOptions(tc.apiPath)...)
		require.NoError(t, err, "an API path is valid with a gateway client")
		require.Equal(t, tc.want, client.BaseURL(), "%q %q", tc.gatewayURL, tc.apiPath)
		require.Equal(t, []string{tc.want + "models"}, listModels(t, client, gw.secure))
	}
	gw, err := unverifiedGatewayHTTPClient(&GatewayOptions{ModelPins: testModelPins, Catalog: func() Catalog { return Catalog{} }})
	require.NoError(t, err)
	client, err := NewOpenAIClient(gw, WithAPIPath("/v1/../admin/"))
	require.Nil(t, client)
	require.ErrorIs(t, err, ErrConfiguration, "the API path is checked as for the other clients")
}

func TestWithAPIPathGivenTwice(t *testing.T) {
	c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
	require.NoError(t, err)
	client, err := NewOpenAIClient(c, WithAPIPath("/first/"), option.WithMaxRetries(0), WithAPIPath("/second/"))
	require.NoError(t, err)
	require.Equal(t, "https://enclave.example/second/", client.BaseURL(), "the last WithAPIPath wins")
	require.Equal(t, []string{"https://enclave.example/second/models"}, listModels(t, client, c.secure))

	client, err = NewOpenAIClient(c, WithAPIPath("/v1/../admin/"), WithAPIPath("/v1/"))
	require.Nil(t, client)
	require.ErrorIs(t, err, ErrConfiguration, "an invalid WithAPIPath is refused even when a later one is valid")
}

func TestWithAPIPathPerRequestFailsTheRequest(t *testing.T) {
	c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
	require.NoError(t, err)
	client, err := NewOpenAIClient(c, WithAPIPath("/openai/v1/"))
	require.NoError(t, err)
	rec := &recordingTransport{}
	c.secure.Transport = rec
	_, err = client.Models.List(context.Background(), WithAPIPath("/other/"))
	require.ErrorIs(t, err, ErrConfiguration)
	require.ErrorContains(t, err, "configures the client, not a request")
	require.Empty(t, rec.urls, "nothing is sent")
}

func TestNewClientChecksWithAPIPathBeforeNetworkIO(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	var requested []string
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requested = append(requested, req.URL.String())
		return nil, errors.New("no network in this test")
	})
	client, err := NewClient(t.Context(), WithAPIPath("v1/"))
	require.Nil(t, client)
	require.ErrorIs(t, err, ErrConfiguration)
	require.Empty(t, requested, "router discovery doesn't start")
}

// embeddingClient embeds an attested client, so it implements
// AttestedHTTPClient without being one.
type embeddingClient struct{ *EnclaveHTTPClient }

func TestOpenAIClientRejectsOtherHTTPClients(t *testing.T) {
	c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
	require.NoError(t, err)
	for name, hc := range map[string]AttestedHTTPClient{
		"nil":                   nil,
		"nil enclave client":    (*EnclaveHTTPClient)(nil),
		"nil router client":     (*RouterHTTPClient)(nil),
		"nil gateway client":    (*GatewayHTTPClient)(nil),
		"zero enclave client":   &EnclaveHTTPClient{},
		"zero router client":    &RouterHTTPClient{},
		"zero gateway client":   &GatewayHTTPClient{},
		"type embedding one":    embeddingClient{c},
		"pointer embedding one": &embeddingClient{c},
	} {
		client, err := NewOpenAIClient(hc)
		require.Nil(t, client, name)
		require.ErrorIs(t, err, ErrConfiguration, name)
	}
}

func TestOpenAIClientSurfacesSDKErrors(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	synctest.Test(t, func(t *testing.T) {
		http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("no network in this test")
		})
		c, err := unverifiedEnclaveHTTPClient("enclave.example", RepoPin{Repo: "org/repo"}, nil)
		require.NoError(t, err)
		client, err := NewOpenAIClient(c, option.WithMaxRetries(0))
		require.NoError(t, err)

		_, err = client.Models.List(context.Background(), option.WithBaseURL("https://evil.example/v1/"))
		require.ErrorIs(t, err, ErrConfiguration, "a per-request base URL on another origin is refused")

		_, err = client.Models.List(context.Background())
		require.ErrorIs(t, err, ErrNetwork, "a failed verification keeps its category through the OpenAI client")
	})
}

// NewClient returns the same OpenAIClient type as NewOpenAIClient.
var _ func(context.Context, ...option.RequestOption) (*OpenAIClient, error) = NewClient
