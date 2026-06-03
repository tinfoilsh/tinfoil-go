package tinfoil

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/openai/openai-go/v3/option"
	log "github.com/sirupsen/logrus"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// TransportMode selects how the SDK secures traffic to the enclave.
type TransportMode string

const (
	// TransportEHBP encrypts request bodies end-to-end with HPKE via the
	// Encrypted HTTP Body Protocol. Only the verified enclave can decrypt them,
	// so it works through proxies. This is the default.
	TransportEHBP TransportMode = "ehbp"

	// TransportTLS pins the enclave's TLS certificate. All traffic is encrypted
	// and terminated at the verified enclave, which requires a direct
	// connection (requests through a proxy will fail).
	TransportTLS TransportMode = "tls"
)

const (
	defaultTransportMode = TransportEHBP
	defaultConfigRepo    = "tinfoilsh/confidential-model-router"
)

type clientConfig struct {
	enclave    string
	repo       string
	transport  TransportMode
	openaiOpts []option.RequestOption
}

// ClientOption configures a Client created with NewClientWithOptions.
type ClientOption func(*clientConfig)

// WithEnclave sets the enclave host to verify and connect to. When unset, a
// router is selected automatically.
func WithEnclave(enclave string) ClientOption {
	return func(c *clientConfig) { c.enclave = enclave }
}

// WithRepo sets the GitHub repository used for code measurement verification.
func WithRepo(repo string) ClientOption {
	return func(c *clientConfig) { c.repo = repo }
}

// WithTransport selects the transport mode. Defaults to TransportEHBP.
func WithTransport(mode TransportMode) ClientOption {
	return func(c *clientConfig) { c.transport = mode }
}

// WithOpenAIOptions appends options passed through to the underlying OpenAI client.
func WithOpenAIOptions(opts ...option.RequestOption) ClientOption {
	return func(c *clientConfig) { c.openaiOpts = append(c.openaiOpts, opts...) }
}

// NewClientWithOptions creates a secure OpenAI client configured through
// functional options. By default it selects a router automatically, verifies
// against the default config repository, and uses the EHBP transport.
func NewClientWithOptions(opts ...ClientOption) (*Client, error) {
	cfg := &clientConfig{
		repo:      defaultConfigRepo,
		transport: defaultTransportMode,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.transport == "" {
		cfg.transport = defaultTransportMode
	}
	if cfg.repo == "" {
		cfg.repo = defaultConfigRepo
	}

	var secureClient *client.SecureClient
	if cfg.enclave == "" {
		var err error
		secureClient, err = client.NewDefaultClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create secure client: %w", err)
		}
	} else {
		secureClient = client.NewSecureClient(cfg.enclave, cfg.repo)
	}

	return createClientFromSecureClient(secureClient, cfg.transport, cfg.openaiOpts...)
}

// secureHTTPClient builds an *http.Client for the requested transport mode.
func secureHTTPClient(secureClient *client.SecureClient, mode TransportMode) (*http.Client, error) {
	switch mode {
	case TransportTLS:
		return tlsPinnedHTTPClient(secureClient)
	case TransportEHBP, "":
		return ehbpHTTPClient(secureClient)
	default:
		return nil, fmt.Errorf("unknown transport mode: %q", mode)
	}
}

// tlsPinnedHTTPClient returns the enclave-pinned HTTP client that re-verifies
// attestation when the server's TLS certificate rotates.
func tlsPinnedHTTPClient(secureClient *client.SecureClient) (*http.Client, error) {
	httpClient, err := secureClient.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Wrap with re-verifying transport to handle certificate rotation
	httpClient.Transport = &reVerifyingTransport{
		secureClient: secureClient,
		transport:    httpClient.Transport,
	}
	return httpClient, nil
}

// ehbpHTTPClient returns an HTTP client whose request bodies are encrypted to
// the enclave's attested HPKE public key and that re-verifies attestation when
// the server rotates its HPKE key.
func ehbpHTTPClient(secureClient *client.SecureClient) (*http.Client, error) {
	groundTruth := secureClient.GroundTruth()
	if groundTruth == nil {
		var err error
		groundTruth, err = secureClient.Verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify enclave: %w", err)
		}
	}

	inner, err := buildEHBPTransport(groundTruth.HPKEPublicKey)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: newEHBPReVerifyingTransport(secureClient, inner),
	}, nil
}

// buildEHBPTransport creates an EHBP round tripper bound to a hex-encoded HPKE
// public key obtained through attestation verification.
func buildEHBPTransport(hpkePublicKeyHex string) (http.RoundTripper, error) {
	if hpkePublicKeyHex == "" {
		return nil, fmt.Errorf("enclave did not expose an HPKE public key; cannot use the EHBP transport (use WithTransport(TransportTLS))")
	}

	serverIdentity, err := ehbpidentity.FromPublicKeyHex(hpkePublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HPKE public key: %w", err)
	}

	transport, err := ehbpclient.NewTransportWithIdentity(serverIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to create EHBP transport: %w", err)
	}
	return transport, nil
}

// ehbpReVerifyingTransport wraps an EHBP round tripper and re-verifies
// attestation when the enclave rotates its HPKE key, mirroring the certificate
// rotation handling of the TLS transport.
type ehbpReVerifyingTransport struct {
	mu        sync.RWMutex
	transport http.RoundTripper

	// reverify re-runs attestation, installs an EHBP transport built from the
	// freshly attested HPKE key, and returns it.
	reverify func() (http.RoundTripper, error)
}

func newEHBPReVerifyingTransport(secureClient *client.SecureClient, inner http.RoundTripper) *ehbpReVerifyingTransport {
	t := &ehbpReVerifyingTransport{transport: inner}
	t.reverify = func() (http.RoundTripper, error) {
		groundTruth, err := secureClient.Verify()
		if err != nil {
			return nil, err
		}

		newTransport, err := buildEHBPTransport(groundTruth.HPKEPublicKey)
		if err != nil {
			return nil, err
		}

		t.mu.Lock()
		t.transport = newTransport
		t.mu.Unlock()
		return newTransport, nil
	}
	return t
}

func (t *ehbpReVerifyingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.RLock()
	transport := t.transport
	t.mu.RUnlock()

	resp, err := transport.RoundTrip(req)
	if err == nil || !ehbpidentity.IsKeyConfigError(err) {
		return resp, err
	}

	// HPKE key configuration mismatch: the request was rejected before being
	// processed, so re-verify attestation, rebuild the transport from the new
	// key, and retry the request once.
	retryReq, bodyErr := resetRequestBody(req)
	if bodyErr != nil {
		return nil, err
	}

	newTransport, reverifyErr := t.reverify()
	if reverifyErr != nil {
		// Re-verification failed; surface the original key mismatch error.
		return nil, err
	}

	log.Info("HPKE key rotation detected, re-verified attestation successfully")
	return newTransport.RoundTrip(retryReq)
}

// resetRequestBody returns a request whose body can be sent again. EHBP
// encryption consumes the body on the first attempt, so a retry needs a fresh
// copy obtained through GetBody.
func resetRequestBody(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("cannot retry request after key rotation: body is not replayable")
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("cannot retry request after key rotation: %w", err)
	}

	retry := req.Clone(req.Context())
	retry.Body = body
	return retry, nil
}
