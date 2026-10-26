package tinfoil

import (
	"context"
	"fmt"
	"net/http"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

// Client wraps the OpenAI client to provide secure inference through Tinfoil
// on its default route.
type Client struct {
	*openai.Client
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	client, err := DiscoverRouterOpenAI(context.Background(), nil, openaiOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create enclave handle: %w", err)
	}
	router := client.HTTPClient()
	return &Client{Client: client.Client, httpClient: router.secure, baseURL: router.openAIURL}, nil
}

// HTTPClient returns the underlying HTTP client used to reach the enclave. It
// re-verifies before new requests when witnesses expire or the enclave rotates its key.
// It is bound to the verified enclave: requests to any other origin are
// refused to avoid disclosing sensitive headers. Under EHBP, only request and
// response bodies are sealed to the enclave; a request without a body is not.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// BaseURL returns the URL the client sends requests to on the route it chose.
// Build raw request URLs for HTTPClient from it so they follow the route.
func (c *Client) BaseURL() string {
	return c.baseURL
}
