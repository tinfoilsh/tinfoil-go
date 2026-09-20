package tinfoil

import (
	"fmt"
	"net/http"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// Client is an OpenAI client with enclave verification.
type Client struct {
	*openai.Client
	secureClient *client.SecureClient
	httpClient   *http.Client
	transport    TransportMode
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
		transport:    mode,
	}, nil
}

func (c *Client) Enclave() string {
	return c.secureClient.Enclave()
}

func (c *Client) Repo() string {
	return c.secureClient.Repo()
}

// Transport returns the transport mode used to secure traffic to the enclave.
func (c *Client) Transport() TransportMode {
	return c.transport
}

// Verify refreshes attestation and returns the verified state.
func (c *Client) Verify() (*client.VerifiedDocumentV3, error) {
	return c.secureClient.Verify()
}

// Verification returns a copy of the last successful verification.
func (c *Client) Verification() *client.VerifiedDocumentV3 {
	return c.secureClient.Verification()
}

// HTTPClient returns an HTTP client restricted to the enclave and configured proxy.
// It re-verifies before new requests when witnesses expire or the enclave rotates its key.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
