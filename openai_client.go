package tinfoil

import (
	"fmt"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

// Client wraps the OpenAI client to work with Tinfoil
type Client struct {
	*openai.Client
	enclave     string
	repo        string
	groundTruth *GroundTruth
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

	client := &Client{
		enclave: enclave,
		repo:    repo,
	}

	// Create the OpenAI client with a verified secure connection
	openaiClient, err := client.createOpenAIClient(openaiOpts...)
	if err != nil {
		return nil, err
	}

	client.Client = openaiClient
	return client, nil
}

// createOpenAIClient sets up the OpenAI client with a secure HTTP client
func (c *Client) createOpenAIClient(opts ...option.RequestOption) (*openai.Client, error) {

	// Verify the enclave and get the certificate fingerprint
	secureClient := NewSecureClient(c.enclave, c.repo)

	// Verify enclave and repo
	groundTruth, err := secureClient.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify enclave: %w", err)
	}
	c.groundTruth = groundTruth

	// Create an HTTP client with our custom transport
	httpClient, err := secureClient.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Add our HTTP client and base URL to the options
	allOpts := append(opts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", c.enclave)),
	)

	// Create the OpenAI client with our custom HTTP client
	client := openai.NewClient(allOpts...)

	return client, nil
}
