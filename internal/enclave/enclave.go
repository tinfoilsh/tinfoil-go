// Package enclave verifies an attested enclave's attestation. An Enclave names
// one enclave and the policy it is verified against, and keeps no state;
// package transport caches what it verifies and ties HTTP traffic to the keys
// it endorses.
package enclave

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// ErrFreshnessExpired means the authenticated witnesses no longer authorize
// requests.
var ErrFreshnessExpired = errors.New("attestation freshness witnesses have expired; retry verification with fresh evidence")

// errNoTLSKey reports a verification with no TLS key to bind a channel to.
var errNoTLSKey = fmt.Errorf("document endorses no %q key", document.CryptoMaterialIDTLS)

const (
	verificationRetries          = 1
	candidateVerificationRetries = 0
	verificationRetryDelay       = time.Second
)

// Config describes an Enclave.
type Config struct {
	// Host is the enclave, a host with an optional port.
	Host string
	// FetchAttestation, when set, obtains the enclave's attestation document
	// instead of a direct fetch from the enclave. What it returns is verified
	// like a fetched document.
	FetchAttestation fetch.Func
	// Pin is what the enclave is verified against.
	Pin verify.Pin
	// Verifier is the policy, which several enclaves can share; nil selects the
	// defaults, under which Pin must name a repository or project.
	Verifier *verify.Verifier
	// VerificationCheck, when set, is called with each verification that
	// passes Verifier. An error rejects the verification without a retry.
	VerificationCheck func(v *verify.Verification) error
}

// Enclave is one enclave and the policy its attestation is verified against.
type Enclave struct {
	host string
	pin  verify.Pin
	// fetchDocument obtains the attestation document.
	fetchDocument fetch.Func
	// verifier is the immutable verification policy, shareable across enclaves.
	verifier *verify.Verifier
	// check is the caller's VerificationCheck, or nil.
	check func(v *verify.Verification) error
	// fetch, when set, replaces fetching and verifying a document, for tests.
	fetch func() (*verify.Verification, error)
}

// NewVerifier builds the verifier that config and policy describe, and reports
// an invalid value as an errs.ErrConfiguration error that wraps verify's
// UsageError.
func NewVerifier(config verify.ConfigTrust, policy verify.Policy) (*verify.Verifier, error) {
	v, err := verify.NewVerifier(config, policy)
	if err != nil {
		return nil, fromVerify(err)
	}
	return v, nil
}

// New checks c.Pin against the verifier's rules and does no network I/O.
func New(c Config) (*Enclave, error) {
	v := c.Verifier
	if v == nil {
		var err error
		if v, err = NewVerifier(nil, verify.Policy{}); err != nil {
			return nil, err
		}
	}
	if err := v.CheckPinVerifiability(c.Pin); err != nil {
		return nil, fromVerify(err)
	}
	fetchDocument := c.FetchAttestation
	if fetchDocument == nil {
		fetchDocument = fetch.Document
	}
	return &Enclave{host: c.Host, pin: c.Pin, fetchDocument: fetchDocument, verifier: v, check: c.VerificationCheck}, nil
}

// NewForTest returns an Enclave for host that verifies by calling fetch
// instead of fetching and verifying a document. It is for the tests of
// packages built on enclave.
func NewForTest(host string, fetch func() (*verify.Verification, error)) *Enclave {
	return &Enclave{host: host, fetch: fetch}
}

// Host returns the enclave host.
func (e *Enclave) Host() string {
	return e.host
}

// Pin returns the pin the enclave is verified against.
func (e *Enclave) Pin() verify.Pin {
	return e.pin
}

// Verifier returns the verification policy, which several enclaves can share.
func (e *Enclave) Verifier() *verify.Verifier {
	return e.verifier
}

// Verify fetches and verifies the enclave's attestation, retrying once after a
// network or attestation failure. The verification it returns is fresh and
// has passed the VerificationCheck.
func (e *Enclave) Verify() (*verify.Verification, error) {
	return e.verify(verificationRetries)
}

// VerifyOnce verifies like Verify but doesn't retry a failed attempt, so a
// caller trying several enclaves moves on quickly.
func (e *Enclave) VerifyOnce() (*verify.Verification, error) {
	return e.verify(candidateVerificationRetries)
}

func (e *Enclave) verify(retries int) (*verify.Verification, error) {
	fetch := e.fetch
	if fetch == nil {
		fetch = e.fetchVerification
	}
	var verified *verify.Verification
	var err, firstErr error
	for attempt := 0; ; attempt++ {
		verified, err = fetch()
		if err == nil {
			err = checkFreshness(verified)
		}
		if err == nil {
			err = e.checkVerification(verified)
		}
		// The VerificationCheck can run past the deadline; a retry fetches
		// fresh evidence.
		if err == nil {
			err = checkFreshness(verified)
		}
		if attempt == retries || !retryableVerification(err) {
			break
		}
		firstErr = err
		time.Sleep(verificationRetryDelay)
	}
	if err != nil {
		if firstErr != nil {
			err = &retriedError{err: err, first: firstErr}
		}
		return nil, err
	}
	return verified, nil
}

// retriedError is the error of a verification that failed again when it was
// retried. It reports the final attempt's error, whose category and types
// errors.Is and errors.As find; the first attempt's error appears only in the
// message, so that the result has one category, as net/http.Transport reports
// only the error of its last attempt.
type retriedError struct {
	err, first error
}

func (e *retriedError) Error() string {
	return fmt.Sprintf("%v (first attempt: %v)", e.err, e.first)
}

func (e *retriedError) Unwrap() error { return e.err }

func (e *Enclave) fetchVerification() (*verify.Verification, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	if err := fetch.CheckTarget(e.host, nonce); err != nil {
		return nil, errs.Configuration(err)
	}
	// A verification can serve many waiting requests, so no single caller's
	// context applies; the fetch is still capped in duration. Each waiting
	// caller's cancellation ends its own wait instead.
	ctx, cancel := context.WithTimeout(context.Background(), fetch.Timeout)
	defer cancel()
	docBytes, err := e.fetchDocument(ctx, e.host, nonce)
	if err != nil {
		// A caller's fetcher may report an SDK category, which it keeps, as
		// a relay's fetch does. Anything else, including the end of ctx, which
		// is the SDK's, is a network error.
		return nil, errs.WrapNetwork(err)
	}

	verified, err := e.verifier.VerifyV3(docBytes, nonce, e.pin)
	if err != nil {
		return nil, fromVerify(err)
	}
	if err := validateTransportKeys(verified); err != nil {
		return nil, err
	}
	return verified, nil
}

// checkFreshness reports a verification whose witnesses no longer authorize
// requests.
func checkFreshness(v *verify.Verification) error {
	if !time.Now().Before(v.FreshnessExpiresAt()) {
		return errs.Attestation(ErrFreshnessExpired)
	}
	return nil
}

// checkVerification runs the caller's VerificationCheck on a copy of v. A
// rejection is a trust decision, so that it is an attestation error whatever
// the check returns: a category in the check's error is not kept.
func (e *Enclave) checkVerification(v *verify.Verification) error {
	if e.check == nil {
		return nil
	}
	if err := e.check(Detached(v)); err != nil {
		return errs.Attestation(&rejectedError{host: e.host, err: errs.Uncategorized(err)})
	}
	return nil
}

// validateTransportKeys requires the keys a transport binds traffic to: the
// TLS key, and the HPKE key when the document endorses one.
func validateTransportKeys(v *verify.Verification) error {
	if err := keyFormat(v, document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format); err != nil {
		return errs.Attestation(err)
	}
	if _, ok := v.TLSPublicKeyFP(); !ok {
		return errs.Attestation(errNoTLSKey)
	}
	if err := keyFormat(v, document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format); err != nil {
		return errs.Attestation(err)
	}
	return nil
}

// keyFormat reports an endorsed id key whose format is not format.
func keyFormat(v *verify.Verification, id, format string) error {
	for _, item := range v.CryptoMaterial() {
		if item.ID == id && item.Format != format {
			return fmt.Errorf("crypto_material item %q has format %q, want %q", id, item.Format, format)
		}
	}
	return nil
}

func retryableVerification(err error) bool {
	var rejected *rejectedError
	if errors.Is(err, errs.ErrConfiguration) || errors.As(err, &rejected) {
		return false
	}
	return errors.Is(err, errs.ErrNetwork) || errors.Is(err, errs.ErrAttestation)
}

// Detached returns a copy of v for a caller to keep. Its fields cannot be
// changed, but a caller holding a pointer can replace the whole value, so
// code that caches a verification never hands out the one it keeps. The copy
// shares v's internals, which only copying accessors can reach.
func Detached(v *verify.Verification) *verify.Verification {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}
