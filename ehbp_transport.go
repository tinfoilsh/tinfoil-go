package tinfoil

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openai/openai-go/v3/option"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

// enclaveURLHeader tells a proxy which enclave to forward an encrypted request
// to, so the request reaches the same enclave the client verified.
const enclaveURLHeader = "X-Tinfoil-Enclave-Url"

// TransportMode selects how the SDK secures traffic to the enclave.
type TransportMode string

const (
	// TransportEHBP encrypts request bodies end-to-end with HPKE via the
	// Encrypted HTTP Body Protocol. Only the verified enclave can decrypt them,
	// so it works through proxies. This is the default.
	TransportEHBP TransportMode = "ehbp"

	// TransportTLS pins the enclave's TLS public key, including for HTTPS-over-CONNECT.
	TransportTLS TransportMode = "tls"
)

const (
	defaultTransportMode = TransportEHBP
	defaultConfigRepo    = "tinfoilsh/confidential-model-router"
)

type clientConfig struct {
	enclave            string
	repo               string
	pins               *measurement.Measurement
	freshnessMaxAge    time.Duration
	transport          TransportMode
	baseURL            string
	baseURLSet         bool
	userCacheSecret    string
	userCacheSecretSet bool
	openaiOpts         []option.RequestOption
}

// ClientOption configures a Client created with NewClientWithOptions.
type ClientOption func(*clientConfig)

// WithEnclave sets the enclave host to verify and connect to. When unset, a
// router is selected automatically.
func WithEnclave(enclave string) ClientOption {
	return func(c *clientConfig) { c.enclave = enclave }
}

// WithRepo sets the trusted repository reference, owner/name[@tag][@sha256:digest].
// A reference other than the default repository requires WithEnclave.
func WithRepo(repo string) ClientOption {
	return func(c *clientConfig) { c.repo = repo }
}

// WithPinnedRegisters adds register pins to code and platform verification.
// Empty entries retain default checks. Requires WithEnclave.
func WithPinnedRegisters(m *measurement.Measurement) ClientOption {
	return func(c *clientConfig) { c.pins = m }
}

// WithFreshnessMaxAge limits code and platform witness age.
// Zero uses the seven-day default; negative values are invalid.
func WithFreshnessMaxAge(maxAge time.Duration) ClientOption {
	return func(c *clientConfig) { c.freshnessMaxAge = maxAge }
}

// WithTransport selects the transport mode. Defaults to TransportEHBP.
func WithTransport(mode TransportMode) ClientOption {
	return func(c *clientConfig) { c.transport = mode }
}

// WithBaseURL routes requests through a proxy. EHBP encrypts bodies to the
// enclave and adds X-Tinfoil-Enclave-Url when the proxy's origin differs.
// TLS requires the verified enclave's HTTPS origin.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *clientConfig) {
		c.baseURL = baseURL
		c.baseURLSet = true
	}
}

// WithOpenAIOptions appends options passed through to the underlying OpenAI client.
func WithOpenAIOptions(opts ...option.RequestOption) ClientOption {
	return func(c *clientConfig) { c.openaiOpts = append(c.openaiOpts, opts...) }
}

// NewClientWithOptions creates an OpenAI client with attestation verification.
// Defaults are router discovery, tinfoilsh/confidential-model-router, and EHBP.
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
	if cfg.baseURLSet {
		if _, err := originOf(cfg.baseURL); err != nil {
			return nil, fmt.Errorf("invalid base URL: %w", err)
		}
	}
	if cfg.enclave == "" && (cfg.pins != nil || cfg.repo != defaultConfigRepo) {
		return nil, fmt.Errorf("custom repository or pinned registers require an enclave")
	}

	verificationOpts := client.VerificationOptions{PinnedRegisters: cfg.pins, FreshnessMaxAge: cfg.freshnessMaxAge}
	var secureClient *client.SecureClient
	var err error
	if cfg.enclave == "" {
		secureClient, err = client.NewDefaultClientWithOptions(verificationOpts)
	} else {
		secureClient, err = client.NewSecureClientWithOptions(cfg.enclave, cfg.repo, verificationOpts)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create secure client: %w", err)
	}

	return createClientFromSecureClient(secureClient, cfg.transport, cfg.baseURL,
		resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet), cfg.openaiOpts...)
}

func secureHTTPClient(secureClient *client.SecureClient, mode TransportMode, baseURL, userCacheSecret string) (*http.Client, error) {
	var (
		httpClient *http.Client
		err        error
	)
	switch mode {
	case TransportTLS:
		httpClient, err = secureClient.HTTPClient()
	case TransportEHBP, "":
		httpClient, err = ehbpHTTPClient(secureClient, baseURL)
	default:
		return nil, fmt.Errorf("unknown transport mode: %q", mode)
	}
	if err != nil {
		return nil, err
	}
	if mode == TransportTLS {
		if err := validateTLSBaseURL(baseURL, secureClient.Enclave()); err != nil {
			return nil, err
		}
	}

	// Inject the cache secret before EHBP encryption or transmission over pinned TLS.
	transport := httpClient.Transport
	if userCacheSecret != "" {
		transport = &userCacheSecretTransport{
			secret:    userCacheSecret,
			transport: transport,
		}
	}

	origins, err := allowedOrigins(secureClient.Enclave(), baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to determine allowed request origins: %w", err)
	}
	httpClient.Transport = &hostBoundRoundTripper{
		allowedOrigins: origins,
		enclave:        secureClient.Enclave(),
		transport:      transport,
	}
	return httpClient, nil
}

func allowedOrigins(enclave, baseURL string) (map[string]struct{}, error) {
	origins := make(map[string]struct{}, 2)
	if enclave != "" {
		origin, err := originOf("https://" + enclave)
		if err != nil {
			return nil, err
		}
		origins[origin] = struct{}{}
	}
	if baseURL != "" {
		origin, err := originOf(baseURL)
		if err != nil {
			return nil, err
		}
		origins[origin] = struct{}{}
	}
	return origins, nil
}

// hostBoundRoundTripper restricts requests to the enclave and configured proxy
// to prevent sending credentials to other origins.
type hostBoundRoundTripper struct {
	allowedOrigins map[string]struct{}
	enclave        string
	transport      http.RoundTripper
}

func (t *hostBoundRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	origin := normalizedOrigin(req.URL)
	if _, ok := t.allowedOrigins[origin]; !ok {
		return nil, fmt.Errorf("refusing to send request to %q: client is bound to enclave %q", origin, t.enclave)
	}
	return t.transport.RoundTrip(req)
}

type transportVerifier interface {
	NewTransport(func(*client.GroundTruth) (http.RoundTripper, error), func(error) bool) (http.RoundTripper, error)
}

func ehbpHTTPClient(secureClient transportVerifier, baseURL string) (*http.Client, error) {
	transport, err := secureClient.NewTransport(func(groundTruth *client.GroundTruth) (http.RoundTripper, error) {
		inner, err := buildEHBPTransport(groundTruth.HPKEPublicKey)
		if err != nil {
			return nil, err
		}
		if headerValue, ok := enclaveURLHeaderValue(baseURL, groundTruth.EnclaveHost); ok {
			return &enclaveURLHeaderTransport{enclaveURL: headerValue, transport: inner}, nil
		}
		return inner, nil
	}, ehbpidentity.IsKeyConfigError)
	if err != nil {
		return nil, fmt.Errorf("creating EHBP transport: %w", err)
	}
	return &http.Client{Transport: transport}, nil
}

func enclaveURLHeaderValue(baseURL, enclave string) (string, bool) {
	if baseURL == "" || enclave == "" {
		return "", false
	}
	enclaveURL := "https://" + enclave
	proxyOrigin, err := originOf(baseURL)
	if err != nil {
		return "", false
	}
	enclaveOrigin, err := originOf(enclaveURL)
	if err != nil {
		return "", false
	}
	if proxyOrigin == enclaveOrigin {
		return "", false
	}
	return enclaveURL, true
}

func originOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("URL must be absolute: %q", rawURL)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("URL must use http or https: %q", rawURL)
	}
	return normalizedOrigin(u), nil
}

// Treat https://host and https://host:443 as the same origin.
func normalizedOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(hostname, port)
	}
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	return scheme + "://" + hostname
}

func validateTLSBaseURL(baseURL, enclave string) error {
	if baseURL == "" {
		return nil
	}

	baseOrigin, err := originOf(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	enclaveOrigin, err := originOf("https://" + enclave)
	if err != nil {
		return err
	}
	if baseOrigin != enclaveOrigin {
		return fmt.Errorf("TLS base URL must use the verified enclave origin %q", enclaveOrigin)
	}
	return nil
}

// The header and HPKE key come from the same verification snapshot.
type enclaveURLHeaderTransport struct {
	enclaveURL string
	transport  http.RoundTripper
}

func (t *enclaveURLHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(enclaveURLHeader, t.enclaveURL)
	return t.transport.RoundTrip(req)
}

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
