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
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// reVerifyingTransport wraps an http.RoundTripper and automatically re-verifies
// attestation on certificate errors, handling server certificate rotation.
type reVerifyingTransport struct {
	mu         sync.RWMutex
	transport  http.RoundTripper
	generation uint64

	reverifyMu sync.Mutex
	reverify   func() (http.RoundTripper, error)
}

func (t *reVerifyingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.RLock()
	transport := t.transport
	generation := t.generation
	t.mu.RUnlock()

	resp, err := transport.RoundTrip(req)
	if err == nil || !isCertificateError(err) {
		return resp, err
	}

	retryReq, bodyErr := resetRequestBody(req)
	if bodyErr != nil {
		return nil, err
	}

	newTransport, reverifyErr := t.reverifyOnce(generation)
	if reverifyErr != nil {
		// Re-verification failed, connection is genuinely malicious.
		return nil, err
	}

	return newTransport.RoundTrip(retryReq)
}

func (t *reVerifyingTransport) reverifyOnce(seenGeneration uint64) (http.RoundTripper, error) {
	t.reverifyMu.Lock()
	defer t.reverifyMu.Unlock()

	t.mu.RLock()
	current, currentGeneration := t.transport, t.generation
	t.mu.RUnlock()
	if currentGeneration != seenGeneration {
		return current, nil
	}

	newTransport, err := t.reverify()
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	t.transport = newTransport
	t.generation++
	t.mu.Unlock()

	log.Info("Certificate rotation detected, re-verified attestation successfully")
	return newTransport, nil
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
	transport     TransportMode
}

// NewClientWithParams creates a new secure OpenAI client with explicit enclave and repo parameters
func NewClientWithParams(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient := client.NewSecureClient(enclave, repo)
	return createClientFromSecureClient(secureClient, defaultTransportMode, "", DefaultUserCacheSecret(), openaiOpts...)
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient, err := client.NewDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create secure client: %w", err)
	}
	return createClientFromSecureClient(secureClient, defaultTransportMode, "", DefaultUserCacheSecret(), openaiOpts...)
}

// createClientFromSecureClient is a helper function to create a Client from a SecureClient
func createClientFromSecureClient(secureClient *client.SecureClient, mode TransportMode, baseURL, userCacheSecret string, openaiOpts ...option.RequestOption) (*Client, error) {
	httpClient, err := secureHTTPClient(secureClient, mode, baseURL, userCacheSecret)
	if err != nil {
		return nil, err
	}

	// Route requests through the proxy base URL when set, otherwise straight to
	// the verified enclave.
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

// HTTPClient returns the underlying HTTP client used to reach the enclave. It
// re-verifies attestation automatically when the enclave rotates its key, and
// it is bound to the verified enclave (and the configured proxy, if any):
// requests to any other origin are refused to avoid disclosing sensitive
// headers. This can be used for secure, direct HTTP requests to the enclave.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
