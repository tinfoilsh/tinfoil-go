// Package mobile is the SDK's gomobile surface: the one package bound into
// TinfoilGo.xcframework.
//
// It exists so the Go API does not have to be FFI-shaped. gomobile silently
// drops anything it cannot represent — maps, slices other than []byte, struct
// values, and every type from an unbound package, which includes time.Time and
// context.Context — so a package that is both a Go API and a binding target
// ends up serving neither well. Everything structured therefore crosses as
// JSON, and the shape of that JSON is declared in verification.go rather than
// inherited from whatever the SDK's types happen to look like.
//
// The package performs no I/O. The caller fetches each attestation document
// itself, from AttestationURL with a nonce from NewNonce, and passes the bytes
// to Verifier.Verify. Discovery, retries, caching and freshness enforcement
// are the caller's.
package mobile

import (
	"crypto/rand"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// NewNonce returns a fresh random challenge for one attestation fetch. Pass
// the same bytes to AttestationURL and to Verify, and never reuse them.
func NewNonce() []byte {
	nonce := make([]byte, document.NonceSize)
	// crypto/rand.Read never returns an error; it crashes the program instead.
	rand.Read(nonce)
	return nonce
}

// AttestationURL returns the HTTPS URL to GET host's attestation document
// from with nonce. When relay is not empty the request goes to relay, which
// forwards it to host. Both are a host with an optional port, not a URL.
func AttestationURL(host, relay string, nonce []byte) (string, error) {
	url, err := fetch.URL(host, relay, nonce)
	if err != nil {
		return "", toMobileError(&verify.UsageError{Err: err})
	}
	return url, nil
}

// Verifier appraises attestation documents under one immutable policy. It is
// safe to use from several threads at once.
type Verifier struct {
	inner *verify.Verifier
	// callerAuthorizesConfig is set when the config trust is an embedded
	// config or a config authorizer.
	callerAuthorizesConfig bool
}

// NewVerifier builds a verifier from optionsJSON, a JSON object with an
// optional config_trust and an optional policy, as described on the options
// type in options.go; an empty string selects the defaults. Any unknown or
// malformed member is rejected.
func NewVerifier(optionsJSON string) (_ *Verifier, err error) {
	defer func() { err = toMobileError(err) }()
	config, policy, err := parseOptions(optionsJSON)
	if err != nil {
		return nil, &verify.UsageError{Err: err}
	}
	return newVerifier(config, policy)
}

// NewVerifierWithConfigAuthorizer builds a verifier whose config trust is
// authorizer, which decides which configs are authorized in place of their
// endorsements. policyJSON is the policy object alone, in the shape of the
// policy member that NewVerifier takes; an empty string selects the default
// policy. A repo passed alone to Verify is then refused.
func NewVerifierWithConfigAuthorizer(policyJSON string, authorizer ConfigAuthorizer) (_ *Verifier, err error) {
	defer func() { err = toMobileError(err) }()
	if authorizer == nil {
		return nil, &verify.UsageError{Err: fmt.Errorf("config authorizer must not be nil")}
	}
	policy, err := parsePolicy(policyJSON)
	if err != nil {
		return nil, &verify.UsageError{Err: err}
	}
	return newVerifier(verify.ConfigAuthorizer{Authorize: authorizeWith(authorizer)}, policy)
}

func newVerifier(config verify.ConfigTrust, policy verify.Policy) (*Verifier, error) {
	inner, err := verify.NewVerifier(config, policy)
	if err != nil {
		return nil, err
	}
	var callerAuthorizes bool
	switch config.(type) {
	case verify.EmbeddedConfig, verify.EmbeddedConfigReference, verify.ConfigAuthorizer:
		callerAuthorizes = true
	}
	return &Verifier{inner: inner, callerAuthorizesConfig: callerAuthorizes}, nil
}

// CheckPinVerifiability reports, without a document or network I/O, the usage
// error Verify would return for repo and project whatever the document, so a
// caller can refuse a pin before fetching. Either may be empty.
func (v *Verifier) CheckPinVerifiability(repo, project string) error {
	return toMobileError(v.inner.CheckPinVerifiability(verify.Pin{Repo: repo, Project: project}))
}

// CallerAuthorizesConfig reports whether the caller supplies the config, with
// an embedded config, or approves it, with a config authorizer, rather than a
// pin authenticating it. Such a verifier needs an explicit enclave: it
// cannot be used to discover a router.
func (v *Verifier) CallerAuthorizesConfig() bool {
	return v.callerAuthorizesConfig
}

// Verify appraises doc, the attestation document fetched with nonce, against
// repo, a GitHub owner/name[@tag][@sha256:digest], and project, a registry
// org/project[@revision][@sha256:digest], and returns what it proved as the
// JSON described in verification.go. Either may be empty; neither is satisfied
// by the other's collateral. A result that can no longer authorize a request
// is an error, as in the Go SDK.
func (v *Verifier) Verify(doc, nonce []byte, repo, project string) (string, error) {
	return v.verifyAt(doc, nonce, verify.Pin{Repo: repo, Project: project}, time.Now(), time.Now)
}

// verifyAt is Verify with the clocks given: the document is appraised at at,
// and the result must still be fresh at now(), read once appraisal is done.
func (v *Verifier) verifyAt(doc, nonce []byte, pin verify.Pin, at time.Time, now func() time.Time) (_ string, err error) {
	defer func() { err = toMobileError(err) }()
	verified, err := v.inner.VerifyV3At(doc, nonce, pin, at)
	if err != nil {
		return "", err
	}
	if err := checkFresh(verified, now()); err != nil {
		return "", err
	}
	return encode(verified)
}

// checkFresh rejects a verification whose witnesses expired by now, so a
// caller enforcing FreshnessExpiresAt does not re-verify in a loop.
func checkFresh(verified *verify.Verification, now time.Time) error {
	if !now.Before(verified.FreshnessExpiresAt()) {
		return &verify.VerificationError{Layer: verify.LayerProvenance, Err: fmt.Errorf("attestation freshness witnesses expired at %s", verified.FreshnessExpiresAt().UTC().Format(time.RFC3339))}
	}
	return nil
}

func encode(verified *verify.Verification) (string, error) {
	encoded, err := json.Marshal(toVerificationJSON(verified))
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
