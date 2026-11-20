package tinfoil

import (
	"context"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/internal/cachesecret"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/router"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// RouterOptions configures a RouterHTTPClient.
type RouterOptions struct {
	// Transport is TLS or EHBP, and nil selects TLS{}. An EHBP ProxyURL
	// forwards requests to the router that discovery chooses.
	Transport Transport
	// Policy is the verification policy that applies on top of the router's
	// fixed trust; the zero Policy keeps every default. The client copies it,
	// so later changes by the caller have no effect.
	Policy verify.Policy
	// VerificationCheck, when set, is called with each verification that
	// passes Policy, before the client uses the router's keys: for each
	// router tried during discovery, and whenever the client verifies again.
	// Return an error to reject the router. Discovery then moves on to the
	// next router; otherwise verification fails with an ErrAttestation error that
	// wraps the error and isn't retried. Requests wait while it runs, so keep
	// it fast; it may be called concurrently.
	VerificationCheck func(v *verify.Verification) error
	// UserCacheSecret is the default prompt-cache scope for the client's
	// requests. A non-empty user_cache_secret string in a request's JSON body
	// overrides it, so a server can scope the cache to each end user, for
	// example with option.WithJSONSet("user_cache_secret", s). When it is
	// empty, the client uses a random secret that is generated in memory once
	// per process and that every client in the process shares; no environment
	// variable or file is read. Applications that want a stable secret across
	// processes or machines pass it here.
	// Use an opaque random value, not a raw user ID or API key.
	UserCacheSecret string
}

// RouterHTTPClient is an *http.Client whose requests reach only the attested
// router it discovered.
type RouterHTTPClient struct {
	*http.Client
	attestedClient
}

// NewRouterHTTPClient returns a client for the first router from Tinfoil's
// router list that passes verification, and otherwise for
// inference.tinfoil.sh, verified before it returns. It checks opts before any
// network I/O, tries routers for at most 30 seconds before falling back, and
// discovers again each time it is called. The client verifies its router
// again by itself when the verification expires or is rejected.
func NewRouterHTTPClient(ctx context.Context, opts *RouterOptions) (*RouterHTTPClient, error) {
	if opts == nil {
		opts = &RouterOptions{}
	}
	tr, err := resolveTransport(opts.Transport)
	if err != nil {
		return nil, err
	}
	verifier, err := enclave.NewVerifier(nil, opts.Policy)
	if err != nil {
		return nil, err
	}
	keyed, err := router.Discover(ctx, verifier, opts.VerificationCheck, func(e *enclave.Enclave) *transport.Transport {
		return keyedTransport(tr, e)
	})
	if err != nil {
		return nil, err
	}
	secret := cachesecret.Resolve(opts.UserCacheSecret)
	a, err := newAttestedClient(keyed, proxyURLOf(tr), secret)
	if err != nil {
		return nil, err
	}
	// Discovery leaves its fallback unverified.
	if _, err := a.EnsureVerified(ctx); err != nil {
		return nil, err
	}
	return &RouterHTTPClient{Client: a.embedded(), attestedClient: a}, nil
}
