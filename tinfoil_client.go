package tinfoil

import (
	"fmt"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

// Client wraps the OpenAI client to provide secure inference through Tinfoil
type Client struct {
	*openai.Client
	enclave string
	repo    string
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient := NewSecureClient()
	return createClientFromSecureClient(secureClient, openaiOpts...)
}

// NewClientWithParams creates a new secure OpenAI client with explicit enclave and repo parameters
func NewClientWithParams(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient := NewSecureClientWithParams(enclave, repo)
	return createClientFromSecureClient(secureClient, openaiOpts...)
}

// createClientFromSecureClient is a helper function to create a Client from a SecureClient
func createClientFromSecureClient(secureClient *SecureClient, openaiOpts ...option.RequestOption) (*Client, error) {
	// Create an HTTP client with our custom transport
	httpClient, err := secureClient.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Add our HTTP client and base URL to the options
	allOpts := append(openaiOpts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", secureClient.enclave)),
	)

	client := openai.NewClient(allOpts...)
	return &Client{
		Client:  &client,
		enclave: secureClient.enclave,
		repo:    secureClient.repo,
	}, nil
}
