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
}

// NewVerifier builds a verifier from optionsJSON, a JSON object whose members
// are described on the options type in options.go; an empty string selects the
// defaults. Any unknown or malformed member is rejected.
func NewVerifier(optionsJSON string) (*Verifier, error) {
	return newVerifier(optionsJSON, nil)
}

// NewVerifierWithConfigAuthorizer builds a verifier as NewVerifier does, with
// authorizer deciding which configs are authorized in place of their
// endorsements. It conflicts with config_signing_keys_pem, config_registry_ids
// and embedded_config, and a repo passed to Verify must then be empty.
func NewVerifierWithConfigAuthorizer(optionsJSON string, authorizer ConfigAuthorizer) (*Verifier, error) {
	if authorizer == nil {
		return nil, toMobileError(&verify.UsageError{Err: fmt.Errorf("config authorizer must not be nil")})
	}
	return newVerifier(optionsJSON, authorizer)
}

func newVerifier(optionsJSON string, authorizer ConfigAuthorizer) (_ *Verifier, err error) {
	defer func() { err = toMobileError(err) }()
	opts, err := parseOptions(optionsJSON)
	if err != nil {
		return nil, &verify.UsageError{Err: err}
	}
	if authorizer != nil {
		opts = append(opts, verify.WithConfigAuthorizer(authorizeWith(authorizer)))
	}
	inner, err := verify.NewVerifier(opts...)
	if err != nil {
		return nil, err
	}
	return &Verifier{inner: inner}, nil
}

// CheckRepoVerifiability reports, without a document or network I/O, whether
// the verifier can verify an enclave against repo, so that a caller can refuse
// a pin before fetching anything. It returns a usage error for a malformed
// repo, for any non-empty repo when a config authorizer is set, and for a repo
// that an embedded config's name or digest doesn't match. Verify can still
// return a usage error for a repo that passes: v3 collateral also requires the
// repo to be a valid config identity, which waits for the document.
func (v *Verifier) CheckRepoVerifiability(repo string) error {
	return toMobileError(v.inner.CheckRepoVerifiability(repo))
}

// CallerAuthorizesConfig reports whether the caller supplies the config, with
// an embedded config, or approves it, with a config authorizer, rather than a
// repo pin authenticating it. Such a verifier needs an explicit enclave: it
// cannot be used to discover a router.
func (v *Verifier) CallerAuthorizesConfig() bool {
	return v.inner.CallerAuthorizesConfig()
}

// Verify appraises doc, the attestation document fetched with nonce, against
// repo, a trusted owner/name[@tag][@sha256:digest] reference, and returns what
// it proved as the JSON described in verification.go. A result that can no
// longer authorize a request is an error, as in the Go SDK.
func (v *Verifier) Verify(doc, nonce []byte, repo string) (_ string, err error) {
	defer func() { err = toMobileError(err) }()
	verified, err := v.inner.VerifyV3(doc, nonce, repo)
	if err != nil {
		return "", err
	}
	if err := checkFresh(verified, time.Now()); err != nil {
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
