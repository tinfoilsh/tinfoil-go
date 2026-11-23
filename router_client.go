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
	// VerificationCheck, when set, is called with the verified facts of each
	// verification that passes Policy, before the client uses the router's
	// keys: for each router tried during discovery, and whenever the client
	// verifies again. Return an error to reject the router. Discovery then
	// moves on to the next router; otherwise verification fails with an
	// ErrAttestation error that wraps the error and isn't retried. Requests
	// wait while it runs, so keep it fast; it may be called concurrently.
	VerificationCheck func(v *verify.VerifiedFacts) error
	// OnVerification, when set, is called once for every attempt to verify a
	// router, after the attempt's outcome is decided, as
	// EnclaveOptions.OnVerification describes: for each router that
	// discovery tries, including the fallback, each with its own host, and
	// for the chosen router whenever the client verifies it again.
	OnVerification func(host string, report *verify.VerificationReport, err error)
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
	// FetchAttestation, when set, obtains the attestation documents of the
	// routers that discovery tries, of the fallback and of the chosen router
	// whenever it is verified again, for example through an AttestationRelay
	// on the application's own origin; nil fetches them directly from each
	// router. Every document is verified as a fetched one is.
	FetchAttestation AttestationFetcher
	// FetchRouterList, when set, obtains the list of candidate routers, for
	// example through a RouterListRelay on the application's own origin; nil
	// fetches Tinfoil's list. Discovery runs on the list as on Tinfoil's: it
	// verifies each router that it tries and falls back to
	// inference.tinfoil.sh. See RouterListFetcher for what the list source is
	// trusted with.
	FetchRouterList RouterListFetcher
}

// RouterHTTPClient is an *http.Client whose requests reach only the attested
// router it discovered.
type RouterHTTPClient struct {
	*http.Client
	attestedClient
}

// NewRouterHTTPClient returns a client for the first router that passes
// verification from Tinfoil's router list, or from the list that
// opts.FetchRouterList obtains, and otherwise for inference.tinfoil.sh,
// verified before it returns. It checks opts before any network I/O, tries
// routers for at most 30 seconds before falling back, and discovers again
// each time it is called. The client verifies its router
// again by itself when the verification expires or is rejected.
func NewRouterHTTPClient(ctx context.Context, opts *RouterOptions) (*RouterHTTPClient, error) {
	if opts == nil {
		opts = &RouterOptions{}
	}
	tr, err := resolveTransport(opts.Transport)
	if err != nil {
		return nil, err
	}
	fetchAttestation, err := attestationFetchFunc(opts.FetchAttestation)
	if err != nil {
		return nil, err
	}
	listRouters, err := routerListFunc(opts.FetchRouterList)
	if err != nil {
		return nil, err
	}
	verifier, err := enclave.NewVerifier(nil, opts.Policy)
	if err != nil {
		return nil, err
	}
	keyed, err := router.Discover(ctx, router.Options{
		Verifier:       verifier,
		Check:          opts.VerificationCheck,
		OnVerification: opts.OnVerification,
		NewTransport: func(e *enclave.Enclave) *transport.Transport {
			return keyedTransport(tr, e)
		},
		List:             listRouters,
		FetchAttestation: fetchAttestation,
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
