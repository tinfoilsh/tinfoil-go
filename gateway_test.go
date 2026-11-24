package tinfoil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
)

// TestGatewayEndpointsJoinUnderItsURL runs a gateway client against a fake
// gateway that records what it is sent: the catalog fetch, the attestation
// relay and the OpenAI request all join under the gateway's URL, as under an
// EHBP ProxyURL, whether or not it has a path and ends with a slash.
func TestGatewayEndpointsJoinUnderItsURL(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, tc := range []struct {
		gatewayURL, root string
	}{
		{"", "https://inference-gateway.tinfoil.sh/"},
		{"https://gateway.example", "https://gateway.example/"},
		{"https://gateway.example/", "https://gateway.example/"},
		{"https://gateway.example/mount", "https://gateway.example/mount/"},
		{"https://gateway.example/mount/", "https://gateway.example/mount/"},
	} {
		t.Run(tc.gatewayURL, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var mu sync.Mutex
				var fetched []string
				http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
					mu.Lock()
					fetched = append(fetched, req.URL.String())
					mu.Unlock()
					if req.URL.String() == tc.root+"catalog" {
						return &http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"m": {"repo": "tinfoilsh/m", "hosts": ["replica.example"]}}`)),
							Request:    req,
						}, nil
					}
					return nil, errors.New("no replica in this test")
				})
				gw, err := NewGatewayHTTPClient(context.Background(), &GatewayOptions{
					ModelPins: map[string]ModelPin{"m": {Repo: "tinfoilsh/m"}},
					URL:       tc.gatewayURL,
				})
				require.NoError(t, err)
				require.Equal(t, []string{tc.root + "catalog"}, fetched, "the catalog is fetched under the gateway's URL")
				require.Equal(t, strings.TrimSuffix(tc.root, "/"), strings.TrimSuffix(gw.BaseURL(), "/"))

				var sent []string
				client, err := NewOpenAIClient(gw, option.WithMaxRetries(0),
					option.WithMiddleware(func(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
						sent = append(sent, req.URL.String())
						return next(req)
					}))
				require.NoError(t, err)
				require.Equal(t, tc.root+"v1/", client.BaseURL())
				_, err = client.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
					Model:    "m",
					Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("hello")},
				})
				require.ErrorIs(t, err, ErrNetwork, "the replica's attestation can't be fetched")
				require.Equal(t, []string{tc.root + "v1/chat/completions"}, sent, "the request joins the API path under the gateway's URL")
				mu.Lock()
				defer mu.Unlock()
				relayed := fetched[1:]
				require.NotEmpty(t, relayed)
				for _, u := range relayed {
					require.True(t, strings.HasPrefix(u, tc.root+".well-known/tinfoil-attestation?"), "attestation is relayed under the gateway's URL: %s", u)
					require.Contains(t, u, "&enclave=replica.example")
				}
			})
		})
	}
}
