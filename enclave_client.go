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
	// VerificationCheck, when set, is called with the verified facts of each
	// verification that passes the trust argument and Policy, before the
	// client uses the enclave's keys: when the client is created and whenever
	// it verifies again. Return an error to reject the enclave. Verification
	// then fails with an ErrAttestation error that wraps the error and isn't
	// retried. Requests wait while it runs, so keep it fast; it may be called
	// concurrently.
	VerificationCheck func(v *verify.VerifiedFacts) error
	// OnVerificationAttempt, when set, is called once for every attempt to
	// verify the enclave, failed attempts included, after the attempt's
	// outcome is decided: the verification when the client is created, each
	// retry, and every verification again, whether after expiry, after a key
	// rotation or through Reverify. It receives the enclave's host and the
	// attempt's outcome, the same report or error that LastVerificationAttempt
	// returns for it, and the report is a copy for the callback to keep. The client holds none of its locks while
	// it calls the callback, so the callback can call the client, but requests
	// that wait for the verification wait for it too, so keep it fast. A
	// retried attempt is reported, in order, once the verification that
	// retried it is done. The callback can't change the outcome; reject an
	// enclave with VerificationCheck. A panic in the callback is recovered and
	// ignored, so that it never reaches the requests that share the
	// verification.
	OnVerificationAttempt func(host string, report *verify.VerificationReport, err error)
	// FetchAttestation, when set, obtains the enclave's attestation documents,
	// for example through an AttestationRelay on the application's own
	// origin; nil fetches them directly from the enclave. Every document is
	// verified as a fetched one is.
	FetchAttestation AttestationFetcher
}

// EnclaveHTTPClient is an *http.Client whose requests reach only one attested
// enclave. It sends request bodies as they are: it never adds or changes a
// user_cache_secret member, so a caller that points it at Tinfoil's router and
// wants a scoped prompt cache sets that member in each request body.
type EnclaveHTTPClient struct {
	*http.Client
	attestedClient
	// trust is what the enclave is verified under, which no caller shares.
	trust Trust
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
	fetchAttestation, err := attestationFetchFunc(opts.FetchAttestation)
	if err != nil {
		return nil, err
	}
	verifier, err := enclave.NewVerifier(config, opts.Policy)
	if err != nil {
		return nil, err
	}
	e, err := enclave.New(enclave.Config{Host: host, Pin: pin, Verifier: verifier, VerificationCheck: opts.VerificationCheck, OnVerification: opts.OnVerificationAttempt, FetchAttestation: fetchAttestation})
	if err != nil {
		return nil, err
	}
	a, err := newAttestedClient(keyedTransport(tr, e), proxyURLOf(tr), "")
	if err != nil {
		return nil, err
	}
	return &EnclaveHTTPClient{Client: a.embedded(), attestedClient: a, trust: cloneTrust(trust)}, nil
}

// attestedClient is what the enclave and router clients share: the verified
// enclave and the chain their requests go through.
type attestedClient struct {
	keyed *transport.Transport
	// secure is the client OpenAI clients use, which changes to the embedded
	// client can't reach.
	secure  *http.Client
	baseURL string
}

// newAttestedClient sends requests to proxyURL, or directly to the enclave
// when it is empty. A non-empty secret is the cache secret that requests
// carry; an empty one adds none.
func newAttestedClient(keyed *transport.Transport, proxyURL, secret string) (attestedClient, error) {
	host := keyed.Enclave().Host()
	rt, err := enclaveChain(keyed, host, proxyURL, secret)
	if err != nil {
		return attestedClient{}, err
	}
	return attestedClient{
		keyed:   keyed,
		secure:  &http.Client{Transport: rt},
		baseURL: cmp.Or(proxyURL, "https://"+host+"/"),
	}, nil
}

// embedded returns a new *http.Client over the chain, for a client type to
// embed and its caller to change.
func (c *attestedClient) embedded() *http.Client {
	return &http.Client{Transport: c.secure.Transport}
}

// enclaveChain stacks what an enclave client sends through around keyed, from
// the inside out: the proxy header, one replay after a key rejection, the
// cache secret when there is one, and origin pinning. The cache secret sits
// above keyed, so the field that it adds is sealed with the rest of the body
// (EHBP) or sent over the pinned connection (TLS).
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

// Trust returns a copy of the trust argument that the enclave is verified
// under. Changing the copy has no effect on the client.
func (c *EnclaveHTTPClient) Trust() Trust {
	return cloneTrust(c.trust)
}

// EnsureVerified returns the report of a verification that is valid now,
// verifying first only if the cached one has expired or been rejected. It
// also prepares the TLS pin or HPKE key for the report's verified facts, so a
// nil error means requests can be sent. The report is a copy for the caller
// to keep.
func (c *attestedClient) EnsureVerified(ctx context.Context) (*verify.VerificationReport, error) {
	return c.keyed.EnsureVerified(ctx)
}

// Reverify verifies again even if the cached verification is still valid.
// When it fails with an ErrAttestation error, the client discards the cached
// verification and closes the idle connections that were made under it, so
// that no request that starts afterwards is sent under it: the next request
// verifies again, and fails while the problem persists. Requests already in
// flight may complete. A failure of any other category, such as a brief
// outage of the attestation source, keeps the cached verification while it is
// still valid. It returns the new report, a copy for the caller to keep.
func (c *attestedClient) Reverify(ctx context.Context) (*verify.VerificationReport, error) {
	return c.keyed.Reverify(ctx)
}

// CurrentVerification returns, without I/O, the report of the verification
// that the client's requests are bound to now, which for a RouterHTTPClient
// is its chosen router's: the latest successful verification while it is
// fresh, before its verified facts' freshness deadline, and has not been
// discarded. It returns nil before the first
// successful verification, after a failure discarded the verification, such
// as a Reverify that failed with an ErrAttestation error or a key rejection,
// and once the verification has expired, until a later verification succeeds.
// A Reverify that fails in any other way, such as with an ErrNetwork error,
// leaves it unchanged while it is fresh, though LastVerificationAttempt then
// returns the failure.
//
// The client doesn't verify again in the background, so after expiry it
// returns nil until the next request or EnsureVerified verifies again. Its
// result holds at the time of the call: the verification can expire right
// after. Use EnsureVerified to check that requests can be sent, verifying
// when needed. The report is a copy for the caller to keep.
func (c *attestedClient) CurrentVerification() *verify.VerificationReport {
	return c.keyed.CurrentVerification()
}

// LastVerificationAttempt returns the outcome of the client's most recent
// attempt to verify its enclave, or its router for a RouterHTTPClient,
// without I/O: the attempt's report if it passed, and otherwise no report
// and the error that the client reported for the attempt. When the verifier
// rejected the enclave's document, errors.As finds its
// *verify.VerificationError, whose Report shows the step that failed. An
// attempt that failed before the verifier ran, such as a failed fetch, or
// that VerificationCheck rejected, has no report. Every attempt counts: the
// first verification, retries, and every verification again, so a failure
// replaces an earlier success.
//
// It doesn't check freshness, so a report that it returns may have expired
// or been discarded since; CurrentVerification returns the verification that
// requests are bound to now. The report is a copy for the caller to keep.
// Before the first attempt, it returns neither a report nor an error.
func (c *attestedClient) LastVerificationAttempt() (*verify.VerificationReport, error) {
	return c.keyed.LastVerificationAttempt()
}
