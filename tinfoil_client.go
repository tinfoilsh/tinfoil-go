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
	secureClient *client.SecureClient
	mu           sync.RWMutex
	transport    http.RoundTripper
	document     *client.VerificationDocument
	generation   uint64
	reverifyMu   sync.Mutex
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

	t.reverifyMu.Lock()
	defer t.reverifyMu.Unlock()

	t.mu.RLock()
	if t.generation != generation {
		transport = t.transport
		t.mu.RUnlock()
		return transport.RoundTrip(req)
	}
	t.mu.RUnlock()

	// Certificate error detected, re-verify the existing client so its
	// verification document and configured verification mode stay current.
	_, clientErr := t.secureClient.Verify()
	if clientErr != nil {
		// Re-verification failed, connection is genuinely malicious
		return nil, err
	}
	newHTTPClient, clientErr := t.secureClient.HTTPClient()
	if clientErr != nil {
		return nil, err
	}

	// Re-verification succeeded, update transport and retry
	log.Info("Certificate rotation detected, re-verified attestation successfully")

	t.mu.Lock()
	t.transport = newHTTPClient.Transport
	t.document = t.secureClient.VerificationDocument()
	t.generation++
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
	secureClient      *client.SecureClient
	httpClient        *http.Client
	enclave, repo     string
	transport         TransportMode
	verifiedTransport verifiedTransport
}

// NewClientWithParams creates a new secure OpenAI client with explicit enclave and repo parameters
func NewClientWithParams(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient := client.NewSecureClient(enclave, repo)
	return createClientFromSecureClient(secureClient, defaultTransportMode, "", "", resolveUserCacheSecret("", false), openaiOpts...)
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	secureClient, err := client.NewDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create secure client: %w", err)
	}
	return createClientFromSecureClient(secureClient, defaultTransportMode, "", "", resolveUserCacheSecret("", false), openaiOpts...)
}

// createClientFromSecureClient is a helper function to create a Client from a SecureClient
func createClientFromSecureClient(secureClient *client.SecureClient, mode TransportMode, baseURL, attestationBundleURL, userCacheSecret string, openaiOpts ...option.RequestOption) (*Client, error) {
	securedClient, err := secureHTTPClient(secureClient, mode, baseURL, attestationBundleURL, userCacheSecret)
	if err != nil {
		return nil, err
	}
	httpClient := securedClient.client

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
		Client:            &openaiClient,
		secureClient:      secureClient,
		httpClient:        httpClient,
		enclave:           secureClient.Enclave(),
		repo:              secureClient.Repo(),
		transport:         mode,
		verifiedTransport: securedClient.transport,
	}, nil
}

// Enclave returns the enclave traffic is secured to, which EHBP moves as the gateway routes.
func (c *Client) Enclave() string {
	if c.verifiedTransport != nil {
		return c.verifiedTransport.activeEnclave()
	}
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
	if c.verifiedTransport != nil {
		return c.verifiedTransport.verifyAndReplace()
	}
	return c.secureClient.Verify()
}

// VerificationDocument returns the result used by the active secure transport.
func (c *Client) VerificationDocument() *client.VerificationDocument {
	if c.verifiedTransport != nil {
		return c.verifiedTransport.verificationDocument()
	}
	return c.secureClient.VerificationDocument()
}

func (t *reVerifyingTransport) replace(transport http.RoundTripper, document *client.VerificationDocument) {
	t.mu.Lock()
	t.transport = transport
	t.document = document
	t.generation++
	t.mu.Unlock()
}

func (t *reVerifyingTransport) activeEnclave() string {
	return t.secureClient.Enclave()
}

func (t *reVerifyingTransport) verificationDocument() *client.VerificationDocument {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.document.Clone()
}

func (t *reVerifyingTransport) verifyAndReplace() (*client.GroundTruth, error) {
	t.reverifyMu.Lock()
	defer t.reverifyMu.Unlock()

	groundTruth, err := t.secureClient.Verify()
	if err != nil {
		return nil, err
	}
	httpClient, err := t.secureClient.HTTPClient()
	if err != nil {
		return nil, err
	}
	t.replace(httpClient.Transport, t.secureClient.VerificationDocument())
	return groundTruth, nil
}

// HTTPClient returns the underlying HTTP client used to reach the enclave. It
// re-verifies attestation automatically when the enclave rotates its key, and
// it is bound to the verified enclave (and the configured proxy, if any):
// requests to any other origin are refused to avoid disclosing sensitive
// headers. This can be used for secure, direct HTTP requests to the enclave.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
