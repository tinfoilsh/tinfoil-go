package tinfoil

import (
	"cmp"
	"context"
	"errors"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// EnclaveOptions configures an EnclaveHTTPClient.
type EnclaveOptions struct {
	// Transport is TLS or EHBP, and nil selects TLS{}.
	Transport Transport
	// Policy is the verification policy that applies on top of the trust
	// argument; the zero Policy keeps every default. The client copies it, so
	// later changes by the caller have no effect.
	Policy verify.Policy
	// VerificationCheck, when set, is called with each verification that
	// passes the trust argument and Policy, before the client uses the
	// enclave's keys: when the client is created and whenever it verifies
	// again. Return an error to reject the enclave. Verification then fails
	// with an ErrAttestation error that wraps the error and isn't retried.
	// Requests wait while it runs, so keep it fast; it may be called
	// concurrently.
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
// under trust, which names who vouches for the enclave's config, and
// opts.Policy. It checks trust and opts before any network I/O, including that
// trust can be satisfied at all, then verifies the enclave under ctx before
// returning, so a misconfigured client fails here rather than on its first
// request. The client verifies again by itself when the verification expires
// or is rejected.
func NewEnclaveHTTPClient(ctx context.Context, host string, trust Trust, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	c, err := unverifiedEnclaveHTTPClient(host, trust, opts)
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
func unverifiedEnclaveHTTPClient(host string, trust Trust, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	if host == "" {
		return nil, errs.Configuration(errors.New("enclave host is required"))
	}
	config, pin, err := verifierInputs(trust)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &EnclaveOptions{}
	}
	tr, err := resolveTransport(opts.Transport)
	if err != nil {
		return nil, err
	}
	if err := refuseEnclaveOriginProxy(proxyURLOf(tr), host); err != nil {
		return nil, err
	}
	verifier, err := enclave.NewVerifier(config, opts.Policy)
	if err != nil {
		return nil, err
	}
	e, err := enclave.New(enclave.Config{Host: host, Pin: pin, Verifier: verifier, VerificationCheck: opts.VerificationCheck})
	if err != nil {
		return nil, err
	}
	a, err := newAttestedClient(keyedTransport(tr, e), cloneTrust(trust), proxyURLOf(tr), opts.UserCacheSecret)
	if err != nil {
		return nil, err
	}
	return &EnclaveHTTPClient{Client: a.embedded(), attestedClient: a}, nil
}

// attestedClient is what the enclave and router clients share: the verified
// enclave and the chain their requests go through.
type attestedClient struct {
	keyed *transport.Transport
	// trust is what the enclave is verified under, which no caller shares.
	trust Trust
	// secure is the client OpenAI clients use, which changes to the embedded
	// client can't reach.
	secure             *http.Client
	baseURL, openAIURL string
}

// newAttestedClient sends requests to proxyURL, or directly to the enclave
// when it is empty.
func newAttestedClient(keyed *transport.Transport, trust Trust, proxyURL, secret string) (attestedClient, error) {
	host := keyed.Enclave().Host()
	rt, err := enclaveChain(keyed, host, proxyURL, secret)
	if err != nil {
		return attestedClient{}, err
	}
	return attestedClient{
		keyed:     keyed,
		trust:     trust,
		secure:    &http.Client{Transport: rt},
		baseURL:   cmp.Or(proxyURL, "https://"+host+"/"),
		openAIURL: cmp.Or(proxyURL, "https://"+host+"/v1/"),
	}, nil
}

// embedded returns a new *http.Client over the chain, for a client type to
// embed and its caller to change.
func (c *attestedClient) embedded() *http.Client {
	return &http.Client{Transport: c.secure.Transport}
}

// enclaveChain stacks what an enclave client sends through around keyed, from
// the inside out: the proxy header, one replay after a key rejection, the
// cache secret, and origin pinning. The cache secret sits above keyed, so the
// field it adds is sealed with the rest of the body (EHBP) or sent over the
// pinned connection (TLS).
func enclaveChain(keyed http.RoundTripper, host, proxyURL, secret string) (http.RoundTripper, error) {
	rt := transport.WithEnclaveURL(keyed, host, proxyURL)
	rt = transport.WithReplay(rt, transport.IsKeyRejection)
	rt = transport.WithCacheSecret(rt, secret)
	return transport.WithOriginRestriction(rt, host, proxyURL)
}

// BaseURL returns the URL that requests are sent to: the EHBP ProxyURL, or
// the enclave's own origin when the client connects directly.
func (c *attestedClient) BaseURL() string {
	return c.baseURL
}

// Enclave returns the host of the enclave that the client verifies. It stays
// the enclave's host when requests go through an EHBP ProxyURL.
func (c *attestedClient) Enclave() string {
	return c.keyed.Enclave().Host()
}

// Trust returns a copy of the trust that the enclave is verified under: the
// trust argument for an enclave client, or the router's repository for a
// router client. Changing the copy has no effect on the client.
func (c *attestedClient) Trust() Trust {
	return cloneTrust(c.trust)
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
