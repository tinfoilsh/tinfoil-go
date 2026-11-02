package tinfoil

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// TransportMode selects how a client protects its traffic to an enclave. The
// zero value selects TransportModeTLS, the stronger mode; a proxy BaseURL
// requires choosing TransportModeEHBP.
type TransportMode string

const (
	// TransportModeTLS pins each connection to the attested TLS key. It
	// protects the whole request and response, and needs a direct connection.
	// Its connections take only the proxy, dialer and connection-pool
	// settings of http.DefaultTransport and the roots and verification
	// callbacks of its TLS config; a custom TLS dialer or TLS key log there
	// is an ErrConfiguration error.
	TransportModeTLS TransportMode = "tls"
	// TransportModeEHBP seals request and response bodies to the attested
	// HPKE key, so they stay private through a proxy. The method, URL and
	// headers aren't sealed, and neither is a request without a body or its
	// response. It refuses protocol upgrades, such as WebSockets, and CONNECT
	// tunnels, because nothing after the handshake would be sealed.
	TransportModeEHBP TransportMode = "ehbp"
)

// resolve returns m, or TransportModeTLS for the zero value.
func (m TransportMode) resolve() (TransportMode, error) {
	switch m {
	case "":
		return TransportModeTLS, nil
	case TransportModeTLS, TransportModeEHBP:
		return m, nil
	}
	return "", errs.Configuration(fmt.Errorf("unknown transport mode %q", m))
}

// EnclaveOptions configures an EnclaveHTTPClient.
type EnclaveOptions struct {
	// TransportMode defaults to TransportModeTLS.
	TransportMode TransportMode
	// BaseURL is a path on the enclave's own HTTPS origin, or a proxy on
	// another origin, which requires TransportModeEHBP. Requests to a proxy
	// carry X-Tinfoil-Enclave-Url so it can forward them to the enclave. A
	// proxy must use HTTPS, since EHBP doesn't seal headers such as the API
	// key; http:// is accepted only when its host is localhost or a loopback
	// IP address, for a local development proxy or a sidecar.
	BaseURL string
	// Verifier is the verification policy; nil selects the defaults.
	Verifier *verify.Verifier
	// VerificationCheck, when set, is called with each verification that
	// passes Verifier, before the client uses the enclave's keys: when the
	// client is created and whenever it verifies again. Return an error to
	// reject the enclave. Verification then fails with an ErrAttestation error that
	// wraps the error and isn't retried. Requests wait while it runs, so keep
	// it fast; it may be called concurrently.
	VerificationCheck func(v *verify.Verification) error
	// UserCacheSecret, when set, is the default prompt-cache scope for the
	// client's requests. Only Tinfoil's router reads it, so set it when the
	// enclave is a router. A non-empty user_cache_secret string in a
	// request's JSON body overrides it, so a server can scope the cache to
	// each end user, for example with option.WithJSONSet("user_cache_secret",
	// s). Use an opaque random value, not a raw user ID or API key.
	UserCacheSecret string
}

// EnclaveHTTPClient is an *http.Client whose requests reach only one attested
// enclave.
type EnclaveHTTPClient struct {
	*http.Client
	attestedClient
}

// NewEnclaveHTTPClient returns a client for the enclave at host, verified
// against repo, owner/name[@tag][@sha256:digest]. An empty repo leaves config
// authorization to opts.Verifier. It checks opts before any network I/O, then
// verifies the enclave under ctx before returning, so a misconfigured client
// fails here rather than on its first request. The client verifies again by
// itself when the verification expires or is rejected.
func NewEnclaveHTTPClient(ctx context.Context, host, repo string, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	c, err := unverifiedEnclaveHTTPClient(host, repo, opts)
	if err != nil {
		return nil, err
	}
	if _, err := c.EnsureVerified(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// unverifiedEnclaveHTTPClient is NewEnclaveHTTPClient without the network I/O:
// the client verifies on its first request.
func unverifiedEnclaveHTTPClient(host, repo string, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	if host == "" {
		return nil, errs.Configuration(errors.New("enclave host is required"))
	}
	if opts == nil {
		opts = &EnclaveOptions{}
	}
	mode, err := opts.TransportMode.resolve()
	if err != nil {
		return nil, err
	}
	if opts.BaseURL != "" {
		if err := validateBaseURL(opts.BaseURL); err != nil {
			return nil, err
		}
	}
	e, err := enclave.New(enclave.Config{Host: host, Repo: repo, Verifier: opts.Verifier, VerificationCheck: opts.VerificationCheck})
	if err != nil {
		return nil, err
	}
	a, err := newAttestedClient(keyedTransport(mode, e), mode, opts.BaseURL, opts.UserCacheSecret)
	if err != nil {
		return nil, err
	}
	return &EnclaveHTTPClient{Client: a.embedded(), attestedClient: a}, nil
}

// attestedClient is what the enclave and router clients share: the verified
// enclave and the chain their requests go through.
type attestedClient struct {
	keyed *transport.Transport
	// secure is the client OpenAI clients use, which changes to the embedded
	// client can't reach.
	secure             *http.Client
	baseURL, openAIURL string
}

func newAttestedClient(keyed *transport.Transport, mode TransportMode, baseURL, secret string) (attestedClient, error) {
	host := keyed.Enclave().Host()
	if mode == TransportModeTLS {
		if err := validateTLSBaseURL(baseURL, host); err != nil {
			return attestedClient{}, errs.Configuration(err)
		}
	}
	rt, err := enclaveChain(keyed, host, baseURL, secret)
	if err != nil {
		return attestedClient{}, err
	}
	return attestedClient{
		keyed:     keyed,
		secure:    &http.Client{Transport: rt},
		baseURL:   cmp.Or(baseURL, "https://"+host+"/"),
		openAIURL: cmp.Or(baseURL, "https://"+host+"/v1/"),
	}, nil
}

// embedded returns a new *http.Client over the chain, for a client type to
// embed and its caller to change.
func (c *attestedClient) embedded() *http.Client {
	return &http.Client{Transport: c.secure.Transport}
}

// keyedTransport returns the transport that verifies e and protects mode's
// traffic with the keys it verifies.
func keyedTransport(mode TransportMode, e *enclave.Enclave) *transport.Transport {
	if mode == TransportModeTLS {
		return transport.TLS(e)
	}
	return transport.WithEHBP(nil, e)
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

// BaseURL returns the URL requests are sent to: the BaseURL option, or the
// enclave's own origin.
func (c *attestedClient) BaseURL() string {
	return c.baseURL
}

// Enclave returns the host of the enclave the client verifies. It stays the
// enclave's host when BaseURL is a proxy.
func (c *attestedClient) Enclave() string {
	return c.keyed.Enclave().Host()
}

// Repo returns the repository the enclave is verified against, with any tag
// or digest pins. It is empty when the Verifier option authorizes the config
// instead.
func (c *attestedClient) Repo() string {
	return c.keyed.Enclave().Repo()
}

// EnsureVerified returns a verification that is valid now, verifying first
// only if the cached one has expired or been rejected. It also prepares the
// TLS pin or HPKE key for it, so a nil error means requests can be sent.
func (c *attestedClient) EnsureVerified(ctx context.Context) (*verify.Verification, error) {
	return c.keyed.EnsureVerified(ctx)
}

// Reverify verifies again even if the cached verification is still valid.
func (c *attestedClient) Reverify(ctx context.Context) (*verify.Verification, error) {
	return c.keyed.Reverify(ctx)
}

// Current returns the last successful verification without checking it. It
// may have expired or been rejected; use EnsureVerified for one that is
// valid.
func (c *attestedClient) Current() *verify.Verification {
	return c.keyed.Current()
}

// validateBaseURL requires an absolute URL that keeps request headers private
// on the way to the enclave or proxy: HTTPS, or HTTP to a loopback host, whose
// traffic never leaves the machine.
func validateBaseURL(baseURL string) error {
	origin, err := transport.OriginOf(baseURL)
	if err != nil {
		return errs.Configuration(fmt.Errorf("invalid base URL: %w", err))
	}
	if strings.HasPrefix(origin, "https://") {
		return nil
	}
	u, _ := url.Parse(baseURL) // OriginOf parsed it
	if !isLoopback(u.Hostname()) {
		return errs.Configuration(errors.New("invalid base URL: HTTP is allowed only for localhost or a loopback IP address; use HTTPS to protect request headers"))
	}
	return nil
}

// isLoopback reports whether host, as written, is localhost or a loopback IP
// address. It doesn't resolve other names, so DNS can't make a remote host
// pass.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
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
		return fmt.Errorf("a base URL off the verified enclave origin %q is a proxy, which requires TransportModeEHBP", enclaveOrigin)
	}
	return nil
}
