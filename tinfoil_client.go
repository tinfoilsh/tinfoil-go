package tinfoil

import (
	"fmt"
	"net/http"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// Client wraps the OpenAI client to provide secure inference through Tinfoil
type Client struct {
	*openai.Client
	secureClient  *client.SecureClient
	httpClient    *http.Client
	enclave, repo string
	transport     TransportMode
}

// NewClientWithParams creates a new secure OpenAI client with explicit enclave and repo parameters
func NewClientWithParams(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient := client.NewSecureClient(enclave, repo)
	return createClientFromSecureClient(secureClient, defaultTransportMode, "", resolveUserCacheSecret("", false), openaiOpts...)
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	return NewClientWithOptions(WithOpenAIOptions(openaiOpts...))
}

func createClientFromSecureClient(secureClient *client.SecureClient, mode TransportMode, baseURL, userCacheSecret string, openaiOpts ...option.RequestOption) (*Client, error) {
	httpClient, err := secureHTTPClient(secureClient, mode, baseURL, userCacheSecret)
	if err != nil {
		return nil, err
	}

	resolvedBaseURL := baseURL
	if resolvedBaseURL == "" {
		resolvedBaseURL = fmt.Sprintf("https://%s/v1/", secureClient.Enclave())
	}

	// Apply these last so constructor options cannot replace the verified transport.
	allOpts := append(openaiOpts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(resolvedBaseURL),
	)

	openaiClient := openai.NewClient(allOpts...)
	return &Client{
		Client:       &openaiClient,
		secureClient: secureClient,
		httpClient:   httpClient,
		enclave:      secureClient.Enclave(),
		repo:         secureClient.Repo(),
		transport:    mode,
	}, nil
}

func (c *Client) Enclave() string {
	return c.enclave
}

func (c *Client) Repo() string {
	return c.repo
}

// Transport returns the transport mode used to secure traffic to the enclave.
func (c *Client) Transport() TransportMode {
	return c.transport
}

// Verify re-verifies the enclave attestation and returns the ground truth
func (c *Client) Verify() (*client.GroundTruth, error) {
	return c.secureClient.Verify()
}

// VerificationDocument returns the shared verification used to admit requests.
func (c *Client) VerificationDocument() *client.VerificationDocument {
	return c.secureClient.VerificationDocument()
}

// HTTPClient returns an HTTP client restricted to the enclave and configured proxy.
// It re-verifies before new requests when witnesses expire or the enclave rotates its key.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
