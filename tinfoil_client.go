package tinfoil

import (
    "fmt"

    "github.com/openai/openai-go/v2"
    "github.com/openai/openai-go/v2/option"
    "github.com/tinfoilsh/verifier/client"
)

// Client wraps the OpenAI client to provide secure inference through Tinfoil
type Client struct {
	*openai.Client
	enclave, repo string
}

// NewClientWithParams creates a new secure OpenAI client with explicit enclave and repo parameters
func NewClientWithParams(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient := client.NewSecureClient(enclave, repo)
	return createClientFromSecureClient(secureClient, openaiOpts...)
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	return NewClientWithParams("inference.tinfoil.sh", "tinfoilsh/confidential-inference-proxy", openaiOpts...)
}

// createClientFromSecureClient is a helper function to create a Client from a SecureClient
func createClientFromSecureClient(secureClient *client.SecureClient, openaiOpts ...option.RequestOption) (*Client, error) {
	// Create an HTTP client with our custom transport
	httpClient, err := secureClient.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Add our HTTP client and base URL to the options
	allOpts := append(openaiOpts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", secureClient.Enclave())),
	)

	client := openai.NewClient(allOpts...)
	return &Client{
		Client:  &client,
		enclave: secureClient.Enclave(),
		repo:    secureClient.Repo(),
	}, nil
}

func (c *Client) Enclave() string {
	return c.enclave
}

func (c *Client) Repo() string {
	return c.repo
}
