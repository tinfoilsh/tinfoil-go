package tinfoil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/verifier/client"
)

// reVerifyingTransport wraps an http.RoundTripper and automatically re-verifies
// attestation on certificate errors, handling server certificate rotation.
type reVerifyingTransport struct {
	secureClient *client.SecureClient
	mu           sync.RWMutex
	transport    http.RoundTripper
}

func (t *reVerifyingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.RLock()
	transport := t.transport
	t.mu.RUnlock()

	resp, err := transport.RoundTrip(req)
	if err == nil || !isCertificateError(err) {
		return resp, err
	}

	// Certificate error detected, reinitialize secure client to re-verify attestation
	newSecureClient := client.NewSecureClient(t.secureClient.Enclave(), t.secureClient.Repo())
	newHTTPClient, clientErr := newSecureClient.HTTPClient()
	if clientErr != nil {
		// Re-verification failed, connection is genuinely malicious
		return nil, err
	}

	// Re-verification succeeded, update transport and retry
	log.Info("Certificate rotation detected, re-verified attestation successfully")

	t.mu.Lock()
	t.secureClient = newSecureClient
	t.transport = newHTTPClient.Transport
	t.mu.Unlock()

	return newHTTPClient.Transport.RoundTrip(req)
}

func isCertificateError(err error) bool {
	var certInvalidErr x509.CertificateInvalidError
	var unknownAuthErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certVerifyErr *tls.CertificateVerificationError

	return errors.Is(err, client.ErrNoTLS) ||
		errors.Is(err, client.ErrCertMismatch) ||
		errors.As(err, &certInvalidErr) ||
		errors.As(err, &unknownAuthErr) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &certVerifyErr)
}

// Client wraps the OpenAI client to provide secure inference through Tinfoil
type Client struct {
	*openai.Client
	secureClient  *client.SecureClient
	httpClient    *http.Client
	enclave, repo string
}

// NewClientWithParams creates a new secure OpenAI client with explicit enclave and repo parameters
func NewClientWithParams(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient := client.NewSecureClient(enclave, repo)
	return createClientFromSecureClient(secureClient, openaiOpts...)
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient, err := client.NewDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create secure client: %w", err)
	}
	return createClientFromSecureClient(secureClient, openaiOpts...)
}

// createClientFromSecureClient is a helper function to create a Client from a SecureClient
func createClientFromSecureClient(secureClient *client.SecureClient, openaiOpts ...option.RequestOption) (*Client, error) {
	// Create an HTTP client with our custom transport
	httpClient, err := secureClient.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Wrap with re-verifying transport to handle certificate rotation
	reVerifying := &reVerifyingTransport{
		secureClient: secureClient,
		transport:    httpClient.Transport,
	}
	httpClient.Transport = reVerifying

	// Add our HTTP client and base URL to the options
	allOpts := append(openaiOpts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", secureClient.Enclave())),
	)

	openaiClient := openai.NewClient(allOpts...)
	return &Client{
		Client:       &openaiClient,
		secureClient: secureClient,
		httpClient:   httpClient,
		enclave:      secureClient.Enclave(),
		repo:         secureClient.Repo(),
	}, nil
}

func (c *Client) Enclave() string {
	return c.enclave
}

func (c *Client) Repo() string {
	return c.repo
}

// Verify re-verifies the enclave attestation and returns the ground truth
func (c *Client) Verify() (*client.GroundTruth, error) {
	return c.secureClient.Verify()
}

// HTTPClient returns the underlying HTTP client that is configured with
// automatic certificate re-verification and is restricted to TLS connections
// to the verified enclave. This can be used for secure, direct HTTP requests
// to the enclave.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
