package tinfoil

import (
	"context"
	"errors"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/internal/cachesecret"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/router"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// RouterOptions configures a RouterHTTPClient.
type RouterOptions struct {
	// TransportMode defaults to TransportModeTLS.
	TransportMode TransportMode
	// BaseURL is a proxy that forwards requests to the router discovery
	// chooses, and requires TransportModeEHBP: the router isn't known before
	// discovery, so a BaseURL can't name its origin. Requests carry
	// X-Tinfoil-Enclave-Url so the proxy can forward them. The proxy must use
	// HTTPS, since EHBP doesn't seal headers such as the API key; http:// is
	// accepted only when its host is localhost or a loopback IP address, for a
	// local development proxy or a sidecar.
	BaseURL string
	// Verifier is the verification policy; nil selects the defaults. A
	// verifier that authorizes the config itself is a ConfigurationError,
	// since it needs an explicit enclave.
	Verifier *verify.Verifier
	// VerificationCheck, when set, is called with each verification that
	// passes Verifier, before the client uses the router's keys: for each
	// router tried during discovery, and whenever the client verifies again.
	// Return an error to reject the router. Discovery then moves on to the
	// next router; otherwise verification fails with an AttestationError that
	// wraps the error and isn't retried. Requests wait while it runs, so keep
	// it fast; it may be called concurrently.
	VerificationCheck func(v *verify.Verification) error
	// UserCacheSecret is the default prompt-cache scope for the client's
	// requests; empty resolves it from TINFOIL_USER_CACHE_SECRET or
	// ~/.tinfoil/user_cache_secret. A non-empty user_cache_secret string in a
	// request's JSON body overrides it, so a server can scope the cache to each
	// end user, for example with option.WithJSONSet("user_cache_secret", s).
	// Use an opaque random value, not a raw user ID or API key.
	UserCacheSecret string
}

// RouterHTTPClient is an *http.Client whose requests reach only the attested
// router it discovered. It exists only while the router is Tinfoil's default
// route.
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
	mode, err := opts.TransportMode.resolve()
	if err != nil {
		return nil, err
	}
	if opts.BaseURL != "" {
		if err := validateBaseURL(opts.BaseURL); err != nil {
			return nil, err
		}
		if mode == TransportModeTLS {
			return nil, &ConfigurationError{Err: errors.New("a base URL is a proxy when discovering the router, which requires TransportModeEHBP")}
		}
	}
	if opts.Verifier != nil && opts.Verifier.CallerAuthorizesConfig() {
		return nil, &ConfigurationError{Err: errors.New("caller-authorized config requires an explicit enclave")}
	}
	keyed, err := router.Discover(ctx, opts.Verifier, opts.VerificationCheck, func(e *enclave.Enclave) *transport.Transport {
		return keyedTransport(mode, e)
	})
	if err != nil {
		return nil, err
	}
	secret := cachesecret.Resolve(opts.UserCacheSecret, opts.UserCacheSecret != "")
	a, err := newAttestedClient(keyed, mode, opts.BaseURL, secret)
	if err != nil {
		return nil, err
	}
	// Discovery leaves its fallback unverified.
	if _, err := a.EnsureVerified(ctx); err != nil {
		return nil, err
	}
	return &RouterHTTPClient{Client: a.embedded(), attestedClient: a}, nil
}
