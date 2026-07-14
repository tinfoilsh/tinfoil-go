package tinfoil

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/openai/openai-go/v3/option"
	log "github.com/sirupsen/logrus"
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
	enclave              string
	repo                 string
	transport            TransportMode
	baseURL              string
	baseURLSet           bool
	attestationBundleURL string
	userCacheSecret      string
	userCacheSecretSet   bool
	openaiOpts           []option.RequestOption
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

// WithBaseURL routes requests through the given base URL (for example your own
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

// WithAttestationBundleURL fetches the attestation bundle from the given base
// URL (for example your own proxy) instead of attesting the enclave directly,
// so the client only needs to reach a single origin. The bundle is still
// verified client-side. The enclave host is taken from the verified bundle.
func WithAttestationBundleURL(attestationBundleURL string) ClientOption {
	return func(c *clientConfig) { c.attestationBundleURL = attestationBundleURL }
}

// WithOpenAIOptions appends options passed through to the underlying OpenAI client.
func WithOpenAIOptions(opts ...option.RequestOption) ClientOption {
	return func(c *clientConfig) { c.openaiOpts = append(c.openaiOpts, opts...) }
}

// NewClientWithOptions creates a secure OpenAI client configured through
// functional options. By default it selects a router automatically, verifies
// against the default config repository, and uses the EHBP transport.
func NewClientWithOptions(opts ...ClientOption) (*Client, error) {
	cfg, err := newClientConfig(opts)
	if err != nil {
		return nil, err
	}
	secureClient, err := newSecureClientFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return createClientFromSecureClient(secureClient, cfg.transport, cfg.baseURL,
		resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet), cfg.openaiOpts...)
}

// newClientConfig applies the options over the defaults and validates the
// resulting configuration.
func newClientConfig(opts []ClientOption) (*clientConfig, error) {
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
	return cfg, nil
}

// newSecureClientFromConfig builds the secure client for the configured
// enclave, selecting a router automatically when none is pinned.
func newSecureClientFromConfig(cfg *clientConfig) (*client.SecureClient, error) {
	switch {
	case cfg.attestationBundleURL != "":
		// The verified bundle supplies the enclave host, so the router lookup
		// in NewDefaultClient is unnecessary even when no enclave is set.
		secureClient := client.NewSecureClient(cfg.enclave, cfg.repo)
		secureClient.SetAttestationBundleURL(cfg.attestationBundleURL)
		return secureClient, nil
	case cfg.enclave == "":
		secureClient, err := client.NewDefaultClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create secure client: %w", err)
		}
		return secureClientForRepo(secureClient, cfg.repo), nil
	default:
		return client.NewSecureClient(cfg.enclave, cfg.repo), nil
	}
}

func secureClientForRepo(secureClient *client.SecureClient, repo string) *client.SecureClient {
	if repo == defaultConfigRepo {
		return secureClient
	}
	return client.NewSecureClient(secureClient.Enclave(), repo)
}

// secureHTTPClient builds an *http.Client for the requested transport mode.
//
// The returned client is bound to the verified enclave (and the configured
// proxy, if any). EHBP does not encrypt request headers end-to-end; TLS encrypts
// them in transit, but sending them to another origin would disclose them to
// that endpoint. Requests to any other origin are therefore refused.
func secureHTTPClient(secureClient *client.SecureClient, mode TransportMode, baseURL, userCacheSecret string) (*http.Client, error) {
	httpClient, err := sealingHTTPClient(secureClient, mode, baseURL)
	if err != nil {
		return nil, err
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

	guarded, err := newHostBoundTransport(secureClient.Enclave(), baseURL, transport)
	if err != nil {
		return nil, err
	}
	httpClient.Transport = guarded
	return httpClient, nil
}

// sealingHTTPClient builds the HTTP client for the requested transport mode:
// pinned TLS or EHBP, both re-verifying attestation automatically when the
// enclave rotates its keys. The returned client carries no cache-secret or
// origin-binding layers.
func sealingHTTPClient(secureClient *client.SecureClient, mode TransportMode, baseURL string) (*http.Client, error) {
	var (
		httpClient *http.Client
		err        error
	)
	switch mode {
	case TransportTLS:
		httpClient, err = tlsPinnedHTTPClient(secureClient)
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
	return httpClient, nil
}

// newHostBoundTransport wraps rt so requests may only target the verified
// enclave's HTTPS origin and, when baseURL is non-empty, the base URL's
// origin. Requests to any other origin are refused before credentials or
// request bodies are sent.
func newHostBoundTransport(enclave, baseURL string, rt http.RoundTripper) (http.RoundTripper, error) {
	if rt == nil {
		return nil, fmt.Errorf("transport is required")
	}
	origins, err := allowedOrigins(enclave, baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to determine allowed request origins: %w", err)
	}
	return &hostBoundRoundTripper{
		allowedOrigins: origins,
		enclave:        enclave,
		transport:      rt,
	}, nil
}

// allowedOrigins returns the set of origins a secured request may target: the
// verified enclave and, when set, the proxy base URL.
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
	transport      http.RoundTripper
}

func (t *hostBoundRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	origin := normalizedOrigin(req.URL)
	if _, ok := t.allowedOrigins[origin]; !ok {
		return nil, fmt.Errorf("refusing to send request to %q: client is bound to enclave %q", origin, t.enclave)
	}
	return t.transport.RoundTrip(req)
}

// tlsPinnedHTTPClient returns the enclave-pinned HTTP client that re-verifies
// attestation when the server's TLS certificate rotates.
func tlsPinnedHTTPClient(secureClient *client.SecureClient) (*http.Client, error) {
	httpClient, err := secureClient.HTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Wrap with re-verifying transport to handle certificate rotation
	httpClient.Transport = newTLSReVerifyingTransport(secureClient, httpClient.Transport)
	return httpClient, nil
}

func newTLSReVerifyingTransport(secureClient *client.SecureClient, inner http.RoundTripper) *reVerifyingTransport {
	return &reVerifyingTransport{
		transport: inner,
		reverify: func() (http.RoundTripper, error) {
			// Reuse the configured client so attestation-bundle and
			// pinned-measurement settings remain in force during rotation.
			if _, err := secureClient.Verify(); err != nil {
				return nil, err
			}
			httpClient, err := secureClient.HTTPClient()
			if err != nil {
				return nil, err
			}
			return httpClient.Transport, nil
		},
	}
}

// ehbpHTTPClient returns an HTTP client whose request bodies are encrypted to
// the enclave's attested HPKE public key and that re-verifies attestation when
// the server rotates its HPKE key. When baseURL routes requests through a proxy
// whose origin differs from the enclave's, the client adds the
// X-Tinfoil-Enclave-Url header so the proxy can forward to the verified enclave.
func ehbpHTTPClient(secureClient *client.SecureClient, baseURL string) (*http.Client, error) {
	groundTruth := secureClient.GroundTruth()
	if groundTruth == nil {
		var err error
		groundTruth, err = secureClient.Verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify enclave: %w", err)
		}
	}

	// buildTransport builds an EHBP transport for an attested HPKE key, wrapping
	// it with the enclave-URL header when requests route through a proxy. The
	// enclave host is captured here rather than read per request: re-verification
	// rebuilds the transport with the then-current enclave, which keeps the
	// header correct (including on the retry that follows a key rotation) without
	// an unsynchronized read of the client's mutable state.
	buildTransport := func(hpkePublicKeyHex string) (http.RoundTripper, error) {
		inner, err := buildEHBPTransport(hpkePublicKeyHex)
		if err != nil {
			return nil, err
		}
		if headerValue, ok := enclaveURLHeaderValue(baseURL, secureClient.Enclave()); ok {
			return &enclaveURLHeaderTransport{
				enclaveURL: headerValue,
				transport:  inner,
			}, nil
		}
		return inner, nil
	}

	inner, err := buildTransport(groundTruth.HPKEPublicKey)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: newEHBPReVerifyingTransport(secureClient, inner, buildTransport),
	}, nil
}

// enclaveURLHeaderValue returns the X-Tinfoil-Enclave-Url header value and
// whether it should be injected. The header is only needed when requests are
// routed through a proxy whose origin differs from the verified enclave's.
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

// enclaveURLHeaderTransport injects the X-Tinfoil-Enclave-Url header before
// delegating to the wrapped transport. EHBP leaves request headers in
// plaintext, so the header reaches the proxy while the body stays sealed to the
// enclave's HPKE key. The value is captured when the transport is built; a
// re-verification that swaps in a different enclave rebuilds this transport with
// the new value, which also keeps every retry pointed at the right enclave.
type enclaveURLHeaderTransport struct {
	enclaveURL string
	transport  http.RoundTripper
}

func (t *enclaveURLHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(enclaveURLHeader, t.enclaveURL)
	return t.transport.RoundTrip(req)
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

	transport, err := ehbpclient.NewTransportWithIdentity(
		serverIdentity,
		ehbpclient.WithHTTPClient(&http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create EHBP transport: %w", err)
	}
	return &noBodyReplayTransport{transport: transport}, nil
}

// noBodyReplayTransport prevents the EHBP transport's nested http.Client from
// replaying the caller's plaintext GetBody after EncryptRequestWithContext has
// replaced Body with ciphertext. The outer re-verifying transport retains the
// original request and can still replay it through fresh EHBP encryption after
// an attested key rotation.
type noBodyReplayTransport struct {
	transport http.RoundTripper
}

func (t *noBodyReplayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.GetBody = nil
	return t.transport.RoundTrip(out)
}

// ehbpReVerifyingTransport wraps an EHBP round tripper and re-verifies
// attestation when the enclave rotates its HPKE key, mirroring the certificate
// rotation handling of the TLS transport.
type ehbpReVerifyingTransport struct {
	mu         sync.RWMutex
	transport  http.RoundTripper
	generation uint64

	// reverifyMu serializes re-verification. Re-verification mutates shared
	// attestation state on the SecureClient, which is not safe for concurrent
	// use, so concurrent RoundTrip calls that observe the same key rotation
	// must not run it simultaneously.
	reverifyMu sync.Mutex

	// reverify re-runs attestation and returns an EHBP transport built from the
	// freshly attested HPKE key.
	reverify func() (http.RoundTripper, error)
}

func newEHBPReVerifyingTransport(secureClient *client.SecureClient, inner http.RoundTripper, build func(hpkePublicKeyHex string) (http.RoundTripper, error)) *ehbpReVerifyingTransport {
	return &ehbpReVerifyingTransport{
		transport: inner,
		reverify: func() (http.RoundTripper, error) {
			groundTruth, err := secureClient.Verify()
			if err != nil {
				return nil, err
			}
			return build(groundTruth.HPKEPublicKey)
		},
	}
}

func (t *ehbpReVerifyingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.RLock()
	transport := t.transport
	generation := t.generation
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

	newTransport, reverifyErr := t.reverifyOnce(generation)
	if reverifyErr != nil {
		// Re-verification failed; surface the original key mismatch error.
		return nil, err
	}

	return newTransport.RoundTrip(retryReq)
}

// reverifyOnce re-verifies attestation and installs an EHBP transport built
// from the freshly attested HPKE key. Re-verification is serialized so that
// concurrent RoundTrip calls triggered by the same key rotation do not race on
// the shared SecureClient; callers that arrive after another goroutine has
// already rebuilt the transport reuse the freshly installed one instead of
// re-verifying again.
func (t *ehbpReVerifyingTransport) reverifyOnce(seenGeneration uint64) (http.RoundTripper, error) {
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

	log.Info("HPKE key rotation detected, re-verified attestation successfully")
	return newTransport, nil
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
