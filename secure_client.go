package tinfoil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

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
	secureClient := t.secureClient
	t.mu.RUnlock()

	resp, err := transport.RoundTrip(req)
	if err == nil || !isCertificateError(err) {
		return resp, err
	}

	// Certificate error detected, reinitialize secure client to re-verify attestation
	newSecureClient := client.NewSecureClient(secureClient.Enclave(), secureClient.Repo())
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

// SecureClient provides verified HTTP access to a Tinfoil enclave
// without any OpenAI dependency.
type SecureClient struct {
	verifierClient *client.SecureClient
	httpClient     *http.Client
}

// NewSecureClient creates a new SecureClient with explicit enclave and repo parameters.
func NewSecureClient(enclave, repo string) (*SecureClient, error) {
	verifierClient := client.NewSecureClient(enclave, repo)
	return newSecureClientFromVerifier(verifierClient)
}

// NewDefaultSecureClient creates a new SecureClient using default parameters.
func NewDefaultSecureClient() (*SecureClient, error) {
	verifierClient, err := client.NewDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create secure client: %w", err)
	}
	return newSecureClientFromVerifier(verifierClient)
}

func newSecureClientFromVerifier(verifierClient *client.SecureClient) (*SecureClient, error) {
	httpClient, err := verifierClient.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Wrap with re-verifying transport to handle certificate rotation
	reVerifying := &reVerifyingTransport{
		secureClient: verifierClient,
		transport:    httpClient.Transport,
	}
	httpClient.Transport = reVerifying

	return &SecureClient{
		verifierClient: verifierClient,
		httpClient:     httpClient,
	}, nil
}

// HTTPClient returns the underlying HTTP client that is configured with
// automatic certificate re-verification and is restricted to TLS connections
// to the verified enclave.
func (sc *SecureClient) HTTPClient() *http.Client {
	return sc.httpClient
}

// Enclave returns the enclave hostname.
func (sc *SecureClient) Enclave() string {
	return sc.verifierClient.Enclave()
}

// Repo returns the source repo.
func (sc *SecureClient) Repo() string {
	return sc.verifierClient.Repo()
}

// Verify re-verifies the enclave attestation and returns the ground truth.
func (sc *SecureClient) Verify() (*client.GroundTruth, error) {
	return sc.verifierClient.Verify()
}

// Get issues a GET request to the specified URL using the verified HTTP client.
func (sc *SecureClient) Get(url string) (*http.Response, error) {
	return sc.httpClient.Get(url)
}

// Post issues a POST request to the specified URL using the verified HTTP client.
func (sc *SecureClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	return sc.httpClient.Post(url, contentType, body)
}

// Do sends an HTTP request using the verified HTTP client.
func (sc *SecureClient) Do(req *http.Request) (*http.Response, error) {
	return sc.httpClient.Do(req)
}
