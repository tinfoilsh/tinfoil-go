// Package mobile is the SDK's gomobile surface: the one package bound into
// Tinfoil.xcframework.
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

// options is the policy NewVerifier accepts as JSON.
type options struct {
	PinnedRegisters   *measurementJSON `json:"pinned_registers,omitempty"`
	FreshnessMaxAgeNs int64            `json:"freshness_max_age_ns,omitempty"`
}

// NewVerifier builds a verifier from options, a JSON object with
// pinned_registers and freshness_max_age_ns, a freshness bound in integer
// nanoseconds. Any other member is rejected, and an empty string selects the
// defaults.
func NewVerifier(optionsJSON string) (_ *Verifier, err error) {
	defer func() { err = toMobileError(err) }()
	opts := &options{}
	if optionsJSON != "" {
		opts = nil
		if err := json.Unmarshal([]byte(optionsJSON), &opts, json.RejectUnknownMembers(true)); err != nil {
			return nil, &verify.UsageError{Err: fmt.Errorf("parsing verification options: %w", err)}
		}
		if opts == nil {
			return nil, &verify.UsageError{Err: fmt.Errorf("verification options must be a JSON object")}
		}
	}
	pins, err := opts.PinnedRegisters.expected()
	if err != nil {
		return nil, &verify.UsageError{Err: err}
	}
	inner, err := verify.NewVerifier(
		verify.WithPinnedRegisters(pins),
		verify.WithFreshnessMaxAge(time.Duration(opts.FreshnessMaxAgeNs)),
	)
	if err != nil {
		return nil, err
	}
	return &Verifier{inner: inner}, nil
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
	if !now.Before(verified.FreshnessExpiresAt) {
		return &verify.VerificationError{Layer: verify.LayerProvenance, Err: fmt.Errorf("attestation freshness witnesses expired at %s", verified.FreshnessExpiresAt.UTC().Format(time.RFC3339))}
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
