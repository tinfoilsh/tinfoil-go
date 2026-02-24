package tinfoil

import (
	"fmt"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

// Client wraps the OpenAI client to provide secure inference through Tinfoil
type Client struct {
	*openai.Client
	*SecureClient
}

// NewClientWithParams creates a new secure OpenAI client with explicit enclave and repo parameters
func NewClientWithParams(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	sc, err := NewSecureClient(enclave, repo)
	if err != nil {
		return nil, err
	}
	return newClientFromSecureClient(sc, openaiOpts...)
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	sc, err := NewDefaultSecureClient()
	if err != nil {
		return nil, err
	}
	return newClientFromSecureClient(sc, openaiOpts...)
}

// newClientFromSecureClient is a helper function to create a Client from a SecureClient
func newClientFromSecureClient(sc *SecureClient, openaiOpts ...option.RequestOption) (*Client, error) {
	allOpts := append(openaiOpts,
		option.WithHTTPClient(sc.HTTPClient()),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", sc.Enclave())),
	)

	openaiClient := openai.NewClient(allOpts...)
	return &Client{
		Client:       &openaiClient,
		SecureClient: sc,
	}, nil
}
