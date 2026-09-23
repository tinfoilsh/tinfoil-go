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
	active     func() *client.SecureClient
	httpClient *http.Client
	transport  TransportMode
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient, err := client.NewDefaultClient(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure client: %w", err)
	}
	return createClientFromSecureClient(secureClient, defaultTransportMode, "", resolveUserCacheSecret("", false), openaiOpts...)
}

func createClientFromSecureClient(secureClient *client.SecureClient, mode TransportMode, baseURL, userCacheSecret string, openaiOpts ...option.RequestOption) (*Client, error) {
	httpClient, active, err := secureHTTPClient(secureClient, mode, baseURL, userCacheSecret)
	if err != nil {
		return nil, err
	}

	resolvedBaseURL := baseURL
	if resolvedBaseURL == "" {
		resolvedBaseURL = fmt.Sprintf("https://%s/v1/", secureClient.Enclave())
	}

	// Add our HTTP client and base URL to the options
	allOpts := append(openaiOpts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(resolvedBaseURL),
	)

	openaiClient := openai.NewClient(allOpts...)
	return &Client{
		Client:     &openaiClient,
		active:     active,
		httpClient: httpClient,
		transport:  mode,
	}, nil
}

func (c *Client) Enclave() string {
	return c.active().Enclave()
}

func (c *Client) Repo() string {
	return c.active().Repo()
}

// Transport returns the transport mode used to secure traffic to the enclave.
func (c *Client) Transport() TransportMode {
	return c.transport
}

// Verify refreshes attestation and returns the verified state.
func (c *Client) Verify() (*client.VerifiedDocumentV3, error) {
	return c.active().Verify()
}

// Verification returns a copy of the last successful verification.
func (c *Client) Verification() *client.VerifiedDocumentV3 {
	return c.active().Verification()
}

// HTTPClient returns the underlying HTTP client used to reach the enclave. It
// re-verifies before new requests when witnesses expire or the enclave rotates its key.
// It is bound to the verified enclave (and the configured proxy, if any):
// requests to any other origin are refused to avoid disclosing sensitive
// headers. This can be used for secure, direct HTTP requests to the enclave.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
