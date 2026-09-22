package tinfoil

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/openai/openai-go/v3/option"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
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
	enclave            string
	repo               string
	verification       client.VerificationOptions
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

// WithVerificationOptions sets the policy applied to enclave verification.
// The client copies opts and its pins at construction, including for router discovery.
func WithVerificationOptions(opts client.VerificationOptions) ClientOption {
	return func(c *clientConfig) { c.verification = opts }
}

// WithTransport selects the transport mode. Defaults to TransportEHBP.
func WithTransport(mode TransportMode) ClientOption {
	return func(c *clientConfig) { c.transport = mode }
}

// WithBaseURL routes requests through the given HTTPS base URL (for example your own
// proxy) instead of sending them directly to the enclave. Request bodies stay
// encrypted end-to-end to the verified enclave; when the base URL's origin
// differs from the enclave's, the SDK adds the X-Tinfoil-Enclave-Url header so
// the proxy can forward the encrypted request to the right enclave. Only
// supported with the EHBP transport unless it uses the verified enclave's
// HTTPS origin.
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
	if cfg.transport != TransportTLS && cfg.transport != TransportEHBP {
		return nil, &ConfigurationError{Err: fmt.Errorf("unknown transport mode: %q", cfg.transport)}
	}
	if cfg.baseURLSet {
		origin, err := originOf(cfg.baseURL)
		if err != nil {
			return nil, &ConfigurationError{Err: fmt.Errorf("invalid base URL: %w", err)}
		}
		if !strings.HasPrefix(origin, "https://") {
			return nil, &ConfigurationError{Err: fmt.Errorf("invalid base URL: HTTPS is required to protect request headers")}
		}
	}
	if cfg.enclave == "" && cfg.repo != defaultConfigRepo {
		return nil, &ConfigurationError{Err: fmt.Errorf("custom repository requires an enclave")}
	}

	var secureClient *client.SecureClient
	var err error
	if cfg.enclave == "" {
		secureClient, err = client.NewDefaultClient(&cfg.verification)
	} else {
		secureClient, err = client.NewSecureClient(cfg.enclave, cfg.repo, &cfg.verification)
	}
	if err != nil {
		return nil, err
	}

	return createClientFromSecureClient(secureClient, cfg.transport, cfg.baseURL,
		resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet), cfg.openaiOpts...)
}

func secureHTTPClient(secureClient *client.SecureClient, mode TransportMode, baseURL, userCacheSecret string) (*http.Client, func() *client.SecureClient, error) {
	active := func() *client.SecureClient { return secureClient }
	var httpClient *http.Client
	if mode == TransportTLS {
		var err error
		if httpClient, err = secureClient.HTTPClient(); err != nil {
			return nil, nil, err
		}
		if err := validateTLSBaseURL(baseURL, secureClient.Enclave()); err != nil {
			return nil, nil, &ConfigurationError{Err: err}
		}
	} else {
		seal, err := newSealTransport(secureClient, func(s *client.SecureClient) (http.RoundTripper, error) {
			return ehbpTransport(s, baseURL)
		})
		if err != nil {
			return nil, nil, err
		}
		httpClient, active = &http.Client{Transport: seal}, seal.enclave
	}

	// The cache-secret layer sits above the sealing transport, so the field it
	// injects is encrypted with the rest of the body (EHBP) or sent over the
	// pinned connection (TLS).
	transport := httpClient.Transport
	if userCacheSecret != "" {
		transport = &userCacheSecretTransport{
			secret:    userCacheSecret,
			transport: transport,
		}
	}

	origins, err := allowedOrigins(secureClient.Enclave(), baseURL)
	if err != nil {
		return nil, nil, &ConfigurationError{Err: fmt.Errorf("failed to determine allowed request origins: %w", err)}
	}
	httpClient.Transport = &hostBoundRoundTripper{
		allowedOrigins: origins,
		enclave:        secureClient.Enclave(),
		currentEnclave: func() string { return active().Enclave() },
		transport:      transport,
	}
	return httpClient, active, nil
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

// hostBoundRoundTripper rejects requests to any origin other than the verified
// enclave or the configured proxy. This guards the escape-hatch HTTP client
// (and the OpenAI client) from disclosing sensitive request headers, such as the
// API key, to an arbitrary host.
type hostBoundRoundTripper struct {
	allowedOrigins map[string]struct{}
	enclave        string
	currentEnclave func() string
	transport      http.RoundTripper
}

func (t *hostBoundRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	origin := normalizedOrigin(req.URL)
	_, allowed := t.allowedOrigins[origin]
	if !allowed && t.currentEnclave != nil {
		current, _ := originOf("https://" + t.currentEnclave())
		allowed = origin == current
	}
	if !allowed {
		return nil, &ConfigurationError{Err: fmt.Errorf("refusing to send request to %q: client is bound to enclave %q", origin, t.enclave)}
	}
	return t.transport.RoundTrip(req)
}

type transportVerifier interface {
	NewTransport(func(*client.VerifiedDocumentV3) (http.RoundTripper, error), func(error) bool) (http.RoundTripper, error)
}

func ehbpTransport(secureClient transportVerifier, baseURL string) (http.RoundTripper, error) {
	return secureClient.NewTransport(func(verified *client.VerifiedDocumentV3) (http.RoundTripper, error) {
		key, err := verified.HPKEPublicKey()
		if err != nil {
			return nil, fmt.Errorf("%w; cannot use the EHBP transport (use WithTransport(TransportTLS))", err)
		}
		inner, err := buildEHBPTransport(key)
		if err != nil {
			return nil, &AttestationError{Err: err}
		}
		var proxyOrigin string
		if _, ok := enclaveURLHeaderValue(baseURL, verified.EnclaveHost); ok {
			proxyOrigin, _ = originOf(baseURL)
		}
		return &enclaveRoutingTransport{enclave: verified.EnclaveHost, proxyOrigin: proxyOrigin, transport: inner}, nil
	}, ehbpidentity.IsKeyConfigError)
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

// normalizedOrigin lowercases the scheme and host and drops an explicit
// default port so that origins compare equal regardless of how the URL spells
// them (for example https://host and https://host:443).
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

// enclaveRoutingTransport binds the destination to the same snapshot as the
// HPKE key. Direct requests follow the selected router; a configured proxy
// keeps its URL and receives the selected enclave in a header.
type enclaveRoutingTransport struct {
	enclave     string
	proxyOrigin string
	transport   http.RoundTripper
}

func (t *enclaveRoutingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(sealHeader, t.enclave)
	if t.proxyOrigin != "" && normalizedOrigin(req.URL) == t.proxyOrigin {
		req.Header.Set(enclaveURLHeader, "https://"+t.enclave)
	} else {
		req.URL.Host, req.Host = t.enclave, t.enclave
		req.Header.Del(enclaveURLHeader)
	}
	return t.transport.RoundTrip(req)
}

func buildEHBPTransport(hpkePublicKeyHex string) (http.RoundTripper, error) {
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
