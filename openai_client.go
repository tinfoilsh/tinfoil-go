package tinfoil

import (
	"fmt"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

// Client wraps the OpenAI client to work with Tinfoil
type Client struct {
	*openai.Client
	enclave string
	repo    string
}

// NewClient creates a new secure OpenAI client using environment variables for configuration
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	return NewClientWithParams("", "", openaiOpts...)
}

// NewClientWithParams creates a new secure OpenAI client with explicit enclave and repo parameters
func NewClientWithParams(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	// Use provided parameters or fall back to environment variables
	enclave = getEnvDefault("TINFOIL_ENCLAVE", enclave)
	repo = getEnvDefault("TINFOIL_REPO", repo)

	if enclave == "" || repo == "" {
		return nil, fmt.Errorf("tinfoil: enclave and repo must be specified")
	}

	secureClient := NewSecureClient(enclave, repo)

	// Create an HTTP client with our custom transport
	httpClient, err := secureClient.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Add our HTTP client and base URL to the options
	allOpts := append(openaiOpts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", enclave)),
	)

	client := openai.NewClient(allOpts...)
	return &Client{
		Client:  &client,
		enclave: enclave,
		repo:    repo,
	}, nil
}
