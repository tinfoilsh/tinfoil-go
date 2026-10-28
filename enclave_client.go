package tinfoil

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/cachesecret"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/router"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// TransportMode selects how a client protects its traffic to an enclave. The
// zero value selects the route's default.
type TransportMode string

const (
	// TransportModeTLS pins each connection to the attested TLS key. It
	// protects the whole request and response, and needs a direct connection.
	TransportModeTLS TransportMode = "tls"
	// TransportModeEHBP seals request and response bodies to the attested
	// HPKE key, so they stay private through a proxy. The method, URL and
	// headers aren't sealed, and neither is a request without a body or its
	// response. It refuses protocol upgrades, such as WebSockets, and CONNECT
	// tunnels, because nothing after the handshake would be sealed.
	TransportModeEHBP TransportMode = "ehbp"
)

// resolve returns m, or routeDefault for the zero value.
func (m TransportMode) resolve(routeDefault TransportMode) (TransportMode, error) {
	switch m {
	case "":
		return routeDefault, nil
	case TransportModeTLS, TransportModeEHBP:
		return m, nil
	}
	return "", &ConfigurationError{Err: fmt.Errorf("unknown transport mode %q", m)}
}

// EnclaveOptions configures an EnclaveHTTPClient.
type EnclaveOptions struct {
	// TransportMode defaults to TransportModeTLS for NewEnclaveHTTPClient and
	// to TransportModeEHBP for DiscoverRouter.
	TransportMode TransportMode
	// BaseURL is a path on the enclave's own HTTPS origin, or an HTTPS proxy on
	// another origin, which requires TransportModeEHBP. Requests to a proxy
	// carry X-Tinfoil-Enclave-Url so it can forward them to the enclave.
	// DiscoverRouter requires TransportModeEHBP for any BaseURL, because the
	// router's origin isn't known before discovery.
	BaseURL string
	// Verifier is the verification policy; nil selects the defaults.
	Verifier *verify.Verifier
	// VerificationCheck, when set, is called with each verification that
	// passes Verifier, before the client uses the enclave's keys: on first use
	// and whenever the client verifies again. Return an error to reject the
	// enclave. Verification then fails with an AttestationError that wraps the
	// error and isn't retried, and DiscoverRouter moves on to the next router.
	// Requests wait while it runs, so keep it fast; it may be called
	// concurrently.
	VerificationCheck func(v *verify.Verification) error
	// UserCacheSecret is the default prompt-cache scope for the client's
	// requests. Only Tinfoil's router reads it, so NewEnclaveHTTPClient sends
	// it only when set, while DiscoverRouter resolves an empty one from
	// TINFOIL_USER_CACHE_SECRET or ~/.tinfoil/user_cache_secret. A non-empty
	// user_cache_secret string in a request's JSON body overrides it, so a
	// server can scope the cache to each end user, for example with
	// option.WithJSONSet("user_cache_secret", s). Use an opaque random value,
	// not a raw user ID or API key.
	UserCacheSecret string
}

// EnclaveHTTPClient is an *http.Client whose requests reach only one attested
// enclave.
type EnclaveHTTPClient struct {
	*http.Client
	handle *enclave.Handle
	keyed  *transport.Transport
	// secure is the client OpenAI clients use, which changes to the embedded
	// client can't reach.
	secure             *http.Client
	baseURL, openAIURL string
}

// NewEnclaveHTTPClient returns a client for the enclave at host, verified
// against repo, owner/name[@tag][@sha256:digest]. An empty repo leaves config
// authorization to opts.Verifier. It does no network I/O: the enclave is
// verified on the first request, or by EnsureVerified to fail fast.
func NewEnclaveHTTPClient(host, repo string, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	if host == "" {
		return nil, &ConfigurationError{Err: errors.New("enclave host is required")}
	}
	if opts == nil {
		opts = &EnclaveOptions{}
	}
	mode, err := opts.TransportMode.resolve(TransportModeTLS)
	if err != nil {
		return nil, err
	}
	if opts.BaseURL != "" {
		if err := validateBaseURL(opts.BaseURL); err != nil {
			return nil, err
		}
	}
	handle, err := enclave.NewHandle(enclave.Config{Host: host, Repo: repo, Verifier: opts.Verifier, VerificationCheck: opts.VerificationCheck})
	if err != nil {
		return nil, err
	}
	return newEnclaveHTTPClient(handle, mode, opts.BaseURL, opts.UserCacheSecret)
}

// DiscoverRouter returns a client for the first router from Tinfoil's router
// list that passes verification, and otherwise for inference.tinfoil.sh. It
// tries routers for at most 30 seconds before falling back. It does network
// I/O, and calling it again discovers again. It exists only while the router
// is Tinfoil's default route.
func DiscoverRouter(ctx context.Context, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	if opts == nil {
		opts = &EnclaveOptions{}
	}
	mode, err := opts.TransportMode.resolve(TransportModeEHBP)
	if err != nil {
		return nil, err
	}
	if opts.BaseURL != "" {
		if err := validateBaseURL(opts.BaseURL); err != nil {
			return nil, err
		}
		if mode == TransportModeTLS {
			return nil, &ConfigurationError{Err: errors.New("a base URL requires TransportModeEHBP when discovering the router")}
		}
	}
	if opts.Verifier != nil && opts.Verifier.CallerAuthorizesConfig() {
		return nil, &ConfigurationError{Err: errors.New("caller-authorized config requires an explicit enclave")}
	}
	handle, err := router.Discover(ctx, opts.Verifier, opts.VerificationCheck)
	if err != nil {
		return nil, err
	}
	secret := cachesecret.Resolve(opts.UserCacheSecret, opts.UserCacheSecret != "")
	client, err := newEnclaveHTTPClient(handle, mode, opts.BaseURL, secret)
	if err != nil {
		return nil, err
	}
	// Discovery leaves its fallback unverified.
	if _, err := client.EnsureVerified(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

func newEnclaveHTTPClient(handle *enclave.Handle, mode TransportMode, baseURL, secret string) (*EnclaveHTTPClient, error) {
	if mode == TransportModeTLS {
		if err := validateTLSBaseURL(baseURL, handle.Enclave()); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	}
	keyed := keyedTransport(mode, handle)
	rt, err := enclaveChain(keyed, handle.Enclave(), baseURL, secret)
	if err != nil {
		return nil, err
	}
	secure := &http.Client{Transport: rt}
	return &EnclaveHTTPClient{
		Client:    &http.Client{Transport: secure.Transport},
		handle:    handle,
		keyed:     keyed,
		secure:    secure,
		baseURL:   cmp.Or(baseURL, "https://"+handle.Enclave()+"/"),
		openAIURL: cmp.Or(baseURL, "https://"+handle.Enclave()+"/v1/"),
	}, nil
}

// keyedTransport returns the transport that protects mode's traffic with the
// keys handle verifies.
func keyedTransport(mode TransportMode, handle *enclave.Handle) *transport.Transport {
	if mode == TransportModeTLS {
		return transport.TLS(handle)
	}
	return transport.WithEHBP(nil, handle)
}

// enclaveChain stacks what an enclave client sends through around keyed, from
// the inside out: the proxy header, one replay after a key rejection, the
// cache secret, and origin pinning. The cache secret sits above keyed, so the
// field it adds is sealed with the rest of the body (EHBP) or sent over the
// pinned connection (TLS).
func enclaveChain(keyed http.RoundTripper, host, baseURL, secret string) (http.RoundTripper, error) {
	rt := transport.WithEnclaveURL(keyed, host, baseURL)
	rt = transport.WithReplay(rt, transport.IsKeyRejection)
	rt = transport.WithCacheSecret(rt, secret)
	return transport.WithOriginRestriction(rt, host, baseURL)
}

// BaseURL returns the URL requests are sent to: EnclaveOptions.BaseURL, or the
// enclave's own origin.
func (c *EnclaveHTTPClient) BaseURL() string {
	return c.baseURL
}

// Enclave returns the host of the enclave the client verifies: the host passed
// to NewEnclaveHTTPClient, or the router DiscoverRouter chose. It stays the
// enclave's host when BaseURL is a proxy.
func (c *EnclaveHTTPClient) Enclave() string {
	return c.handle.Enclave()
}

// Repo returns the repository the enclave is verified against, with any tag
// or digest pins: the repo passed to NewEnclaveHTTPClient, or the router's
// for DiscoverRouter. It is empty when EnclaveOptions.Verifier authorizes the
// config instead.
func (c *EnclaveHTTPClient) Repo() string {
	return c.handle.Repo()
}

// EnsureVerified returns a verification that is valid now, verifying first
// only if the cached one has expired or been rejected. It also prepares the
// TLS pin or HPKE key for it, so a nil error means requests can be sent.
func (c *EnclaveHTTPClient) EnsureVerified(ctx context.Context) (*verify.Verification, error) {
	state, err := c.keyed.EnsureVerified(ctx)
	if err != nil {
		return nil, err
	}
	return state.Verification(), nil
}

// Reverify verifies again even if the cached verification is still valid.
func (c *EnclaveHTTPClient) Reverify(ctx context.Context) (*verify.Verification, error) {
	state, err := c.handle.Reverify(ctx)
	if err != nil {
		return nil, err
	}
	return state.Verification(), nil
}

// Current returns the last successful verification without checking it. It
// may have expired or been rejected; use EnsureVerified for one that is
// valid.
func (c *EnclaveHTTPClient) Current() *verify.Verification {
	if state := c.handle.Current(); state != nil {
		return state.Verification()
	}
	return nil
}

// validateBaseURL requires an absolute HTTPS URL, which keeps request headers
// private on the way to the enclave or proxy.
func validateBaseURL(baseURL string) error {
	origin, err := transport.OriginOf(baseURL)
	if err != nil {
		return &ConfigurationError{Err: fmt.Errorf("invalid base URL: %w", err)}
	}
	if !strings.HasPrefix(origin, "https://") {
		return &ConfigurationError{Err: fmt.Errorf("invalid base URL: HTTPS is required to protect request headers")}
	}
	return nil
}

// validateTLSBaseURL requires a TLS base URL to use the enclave's own origin,
// since a pinned connection can't pass through a proxy.
func validateTLSBaseURL(baseURL, enclave string) error {
	if baseURL == "" {
		return nil
	}

	baseOrigin, err := transport.OriginOf(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	enclaveOrigin, err := transport.OriginOf("https://" + enclave)
	if err != nil {
		return err
	}
	if baseOrigin != enclaveOrigin {
		return fmt.Errorf("TLS base URL must use the verified enclave origin %q", enclaveOrigin)
	}
	return nil
}
