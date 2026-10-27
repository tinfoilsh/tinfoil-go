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

func TestOpenAIClientsSendThroughTheirHTTPClient(t *testing.T) {
	for _, tc := range []struct {
		name string
		// newClient returns the OpenAI client, the HTTP client it should send
		// through, and the plain client's embedded client.
		newClient func(t *testing.T, opts ...option.RequestOption) (client *openai.Client, secure, embedded *http.Client)
		wantURL   string
	}{
		{
			name: "enclave",
			newClient: func(t *testing.T, opts ...option.RequestOption) (*openai.Client, *http.Client, *http.Client) {
				c := &EnclaveHTTPClient{Client: &http.Client{}, secure: &http.Client{}, openAIURL: "https://enclave.example/v1/"}
				oc := newEnclaveOpenAIClient(c, opts)
				require.Same(t, c, oc.HTTPClient())
				return oc.Client, c.secure, c.Client
			},
			wantURL: "https://enclave.example/v1/models",
		},
		{
			name: "gateway",
			newClient: func(t *testing.T, opts ...option.RequestOption) (*openai.Client, *http.Client, *http.Client) {
				oc, err := NewGatewayOpenAIClient(&GatewayOptions{
					URL:     "https://gateway.example/v1/",
					Catalog: func() Catalog { return Catalog{} },
				}, opts...)
				require.NoError(t, err)
				return oc.Client, oc.HTTPClient().secure, oc.HTTPClient().Client
			},
			wantURL: "https://gateway.example/v1/models",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secure, caller, replaced := &recordingTransport{}, &recordingTransport{}, &recordingTransport{}
			client, secureClient, embedded := tc.newClient(t,
				option.WithBaseURL("https://evil.example/"),
				option.WithHTTPClient(&http.Client{Transport: caller}),
				option.WithMaxRetries(0),
			)
			secureClient.Transport = secure
			embedded.Transport = replaced

			_, err := client.Models.List(context.Background())
			require.NoError(t, err)
			require.Equal(t, []string{tc.wantURL}, secure.urls)
			require.Empty(t, caller.urls, "the caller's HTTP client is replaced")
			require.Empty(t, replaced.urls, "changing the embedded client doesn't reach the OpenAI client")
		})
	}
}

func TestOpenAIClientsRejectInvalidOptions(t *testing.T) {
	var config *ConfigurationError
	enclave, err := NewEnclaveOpenAIClient("", "org/repo", nil)
	require.Nil(t, enclave)
	require.ErrorAs(t, err, &config)
	router, err := DiscoverRouterOpenAI(context.Background(), &EnclaveOptions{TransportMode: "quic"})
	require.Nil(t, router)
	require.ErrorAs(t, err, &config)
	gateway, err := NewGatewayOpenAIClient(&GatewayOptions{URL: "http://gateway.example/v1/", Catalog: func() Catalog { return Catalog{} }})
	require.Nil(t, gateway)
	require.ErrorAs(t, err, &config)
}
