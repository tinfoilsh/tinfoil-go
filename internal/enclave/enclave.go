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
	// VerificationCheck, when set, is called with the verified facts of each
	// verification that passes Verifier. An error rejects the verification
	// without a retry.
	VerificationCheck func(v *verify.VerifiedFacts) error
	// OnVerification, when set, is called with the outcome of each attempt
	// to verify the enclave, through Notify.
	OnVerification func(host string, report *verify.VerificationReport, err error)
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
	check func(v *verify.VerifiedFacts) error
	// onVerification is the caller's OnVerification, or nil.
	onVerification func(host string, report *verify.VerificationReport, err error)
	// fetch, when set, replaces fetching and verifying a document, for tests.
	fetch func() (*verify.VerificationReport, error)
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
	return &Enclave{host: c.Host, pin: c.Pin, fetchDocument: fetchDocument, verifier: v, check: c.VerificationCheck, onVerification: c.OnVerification}, nil
}

// NewForTest returns an Enclave for host that verifies by calling fetch
// instead of fetching and verifying a document, and reports each attempt to
// onVerification, which may be nil. It is for the tests of packages built on
// enclave.
func NewForTest(host string, fetch func() (*verify.VerificationReport, error), onVerification func(string, *verify.VerificationReport, error)) *Enclave {
	return &Enclave{host: host, fetch: fetch, onVerification: onVerification}
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
// network or attestation failure. The report that it returns is fresh, and
// its verified facts have passed the VerificationCheck. Each attempt that
// fails and is retried is passed to retried, which may be nil, before the
// retry starts; the outcome of the last attempt is Verify's result.
func (e *Enclave) Verify(retried func(error)) (*verify.VerificationReport, error) {
	return e.verify(verificationRetries, retried)
}

// VerifyOnce verifies like Verify but doesn't retry a failed attempt, so a
// caller trying several enclaves moves on quickly. It never calls retried.
func (e *Enclave) VerifyOnce(retried func(error)) (*verify.VerificationReport, error) {
	return e.verify(candidateVerificationRetries, retried)
}

func (e *Enclave) verify(retries int, retried func(error)) (*verify.VerificationReport, error) {
	fetch := e.fetch
	if fetch == nil {
		fetch = e.fetchVerification
	}
	var verified *verify.VerificationReport
	var err, firstErr error
	for attempt := 0; ; attempt++ {
		verified, err = fetch()
		e.nameHost(verified, err)
		if err == nil && verified.VerifiedFacts == nil {
			err = errs.Attestation(errors.New("verification passed without verified facts"))
		}
		if err == nil {
			err = checkFreshness(verified.VerifiedFacts)
		}
		if err == nil {
			err = e.checkVerification(verified.VerifiedFacts)
		}
		// The VerificationCheck can run past the deadline; a retry fetches
		// fresh evidence.
		if err == nil {
			err = checkFreshness(verified.VerifiedFacts)
		}
		if attempt == retries || !retryableVerification(err) {
			break
		}
		firstErr = err
		if retried != nil {
			retried(err)
		}
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

// nameHost sets the enclave's host on the report of an attempt, whether it
// passed or the verifier rejected the document, since the verifier doesn't
// know which host the document came from. Every report that a client hands
// out passes through here.
func (e *Enclave) nameHost(report *verify.VerificationReport, err error) {
	var rejected *verify.VerificationError
	if errors.As(err, &rejected) {
		report = rejected.Report
	}
	if report != nil {
		report.Metadata.Host = e.host
	}
}

// Notify reports the outcome of an attempt to verify the enclave to the
// OnVerification callback, if there is one. The caller must hold no lock that
// the callback could need, and passes a report that no one else holds.
//
// A panic in the callback is recovered and ignored. The callback runs inside a
// verification that concurrent requests share, so a panic that escaped would
// reach every caller waiting for it, and the callback can't change the outcome
// anyway.
func (e *Enclave) Notify(report *verify.VerificationReport, err error) {
	if e.onVerification == nil {
		return
	}
	defer func() { _ = recover() }()
	e.onVerification(e.host, report, err)
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

func (e *Enclave) fetchVerification() (*verify.VerificationReport, error) {
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
		// A caller's fetcher may already report an SDK category.
		return nil, errs.WrapNetwork(err)
	}

	verified, err := e.verifier.VerifyV3(docBytes, nonce, e.pin)
	if err != nil {
		return nil, fromVerify(err)
	}
	if err := validateTransportKeys(verified.VerifiedFacts); err != nil {
		return nil, err
	}
	return verified, nil
}

// checkFreshness reports a verification whose witnesses no longer authorize
// requests.
func checkFreshness(v *verify.VerifiedFacts) error {
	if !time.Now().Before(v.FreshnessExpiresAt()) {
		return errs.Attestation(ErrFreshnessExpired)
	}
	return nil
}

// checkVerification runs the caller's VerificationCheck on a copy of v. A
// rejection is a trust decision, and so an attestation error, without a
// category that the check's error carries.
func (e *Enclave) checkVerification(v *verify.VerifiedFacts) error {
	if e.check == nil {
		return nil
	}
	// Its fields can't be changed, and its accessors return copies.
	facts := *v
	if err := e.check(&facts); err != nil {
		return errs.Attestation(&rejectedError{host: e.host, err: errs.Uncategorized(err)})
	}
	return nil
}

// validateTransportKeys requires the keys a transport binds traffic to: the
// TLS key, and the HPKE key when the document endorses one.
func validateTransportKeys(v *verify.VerifiedFacts) error {
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
func keyFormat(v *verify.VerifiedFacts, id, format string) error {
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
