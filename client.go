package tinfoil

import (
	"context"
	"fmt"
	"net/http"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

// Client is an OpenAI client for Tinfoil's recommended route. Which service
// backs that route can change between releases without changing this API, so
// rely only on what Client documents, not on how the route is served today.
type Client struct {
	*openai.Client
	httpClient *http.Client
	baseURL    string
}

// NewClient returns an OpenAI client for Tinfoil's recommended route,
// verified under ctx before it returns.
func NewClient(ctx context.Context, openaiOpts ...option.RequestOption) (*Client, error) {
	client, err := NewRouterOpenAIClient(ctx, nil, openaiOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}
	router := client.HTTPClient()
	return &Client{Client: client.Client, httpClient: router.secure, baseURL: router.openAIURL}, nil
}

// HTTPClient returns the HTTP client the OpenAI client sends through. It
// verifies the service behind the route again before new requests when the
// verification expires or its key changes. It is bound to that service:
// requests to any other origin are refused to avoid disclosing sensitive
// headers. A request's body and the response to it are protected end to end;
// don't rely on headers, or a request without a body, being private.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// BaseURL returns the URL the client sends requests to on the route it chose.
// Build raw request URLs for HTTPClient from it so they follow the route.
func (c *Client) BaseURL() string {
	return c.baseURL
}
