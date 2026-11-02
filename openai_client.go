package tinfoil

import (
	"context"
	"slices"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

// EnclaveOpenAIClient is an OpenAI client whose requests go through an
// EnclaveHTTPClient, to EnclaveOptions.BaseURL or, when that is unset, the
// enclave's /v1/ API. A per-request option.WithHTTPClient bypasses the
// enclave client and its protections.
type EnclaveOpenAIClient struct {
	*openai.Client
	httpClient *EnclaveHTTPClient
}

// NewEnclaveOpenAIClient creates an EnclaveHTTPClient as NewEnclaveHTTPClient
// does, and an OpenAI client over it. It applies openaiOpts, then sets the
// HTTP client and base URL so that openaiOpts can't replace them.
func NewEnclaveOpenAIClient(ctx context.Context, host, repo string, opts *EnclaveOptions, openaiOpts ...option.RequestOption) (*EnclaveOpenAIClient, error) {
	c, err := NewEnclaveHTTPClient(ctx, host, repo, opts)
	if err != nil {
		return nil, err
	}
	return newEnclaveOpenAIClient(c, openaiOpts), nil
}

func newEnclaveOpenAIClient(c *EnclaveHTTPClient, opts []option.RequestOption) *EnclaveOpenAIClient {
	return &EnclaveOpenAIClient{Client: newOpenAIClient(c.secure, c.openAIURL, opts), httpClient: c}
}

// HTTPClient returns the enclave client the OpenAI client sends through.
func (c *EnclaveOpenAIClient) HTTPClient() *EnclaveHTTPClient {
	return c.httpClient
}

// RouterOpenAIClient is an OpenAI client whose requests go through a
// RouterHTTPClient, to RouterOptions.BaseURL or, when that is unset, the
// router's /v1/ API. A per-request option.WithHTTPClient bypasses the router
// client and its protections.
type RouterOpenAIClient struct {
	*openai.Client
	httpClient *RouterHTTPClient
}

// NewRouterOpenAIClient creates a RouterHTTPClient as NewRouterHTTPClient
// does, and an OpenAI client over it. It applies openaiOpts, then sets the
// HTTP client and base URL so that openaiOpts can't replace them.
func NewRouterOpenAIClient(ctx context.Context, opts *RouterOptions, openaiOpts ...option.RequestOption) (*RouterOpenAIClient, error) {
	c, err := NewRouterHTTPClient(ctx, opts)
	if err != nil {
		return nil, err
	}
	return newRouterOpenAIClient(c, openaiOpts), nil
}

func newRouterOpenAIClient(c *RouterHTTPClient, opts []option.RequestOption) *RouterOpenAIClient {
	return &RouterOpenAIClient{Client: newOpenAIClient(c.secure, c.openAIURL, opts), httpClient: c}
}

// HTTPClient returns the router client the OpenAI client sends through.
func (c *RouterOpenAIClient) HTTPClient() *RouterHTTPClient {
	return c.httpClient
}

// GatewayOpenAIClient is an OpenAI client whose requests go through a
// GatewayHTTPClient, to the gateway's URL. A per-request
// option.WithHTTPClient bypasses the gateway client and its protections.
type GatewayOpenAIClient struct {
	*openai.Client
	httpClient *GatewayHTTPClient
}

// NewGatewayOpenAIClient creates a GatewayHTTPClient as NewGatewayHTTPClient
// does, and an OpenAI client over it. It applies openaiOpts, then sets the
// HTTP client and base URL so that openaiOpts can't replace them.
//
// Experimental: the gateway route is new, and this API may change or be
// removed in a later release.
func NewGatewayOpenAIClient(ctx context.Context, opts *GatewayOptions, openaiOpts ...option.RequestOption) (*GatewayOpenAIClient, error) {
	c, err := NewGatewayHTTPClient(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &GatewayOpenAIClient{Client: newOpenAIClient(c.secure, c.baseURL, openaiOpts), httpClient: c}, nil
}

// HTTPClient returns the gateway client the OpenAI client sends through.
func (c *GatewayOpenAIClient) HTTPClient() *GatewayHTTPClient {
	return c.httpClient
}

// newOpenAIClient appends the HTTP client and base URL last because later
// options win.
func newOpenAIClient(httpClient option.HTTPClient, baseURL string, opts []option.RequestOption) *openai.Client {
	client := openai.NewClient(append(slices.Clone(opts), option.WithHTTPClient(httpClient), option.WithBaseURL(baseURL))...)
	return &client
}
