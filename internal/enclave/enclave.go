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
	// Relay, when set, is a host that fetches attestation from the enclave on
	// the client's behalf.
	Relay string
	// Repo pins a repository or registry project,
	// org/project[@revision][@sha256:digest].
	Repo string
	// Verifier is the policy, which several enclaves can share; nil selects the
	// defaults, which require Repo.
	Verifier *verify.Verifier
	// VerificationCheck, when set, is called with each verification that
	// passes Verifier. An error rejects the verification without a retry.
	VerificationCheck func(v *verify.Verification) error
}

// Enclave is one enclave and the policy its attestation is verified against.
type Enclave struct {
	host, repo, relay string
	// verifier is the immutable verification policy, shareable across enclaves.
	verifier *verify.Verifier
	// check is the caller's VerificationCheck, or nil.
	check func(v *verify.Verification) error
	// fetch, when set, replaces fetching and verifying a document, for tests.
	fetch func() (*verify.Verification, error)
}

// New checks c.Repo against the verifier's rules for a repository pin and
// does no network I/O.
func New(c Config) (*Enclave, error) {
	v := c.Verifier
	if v == nil {
		var err error
		if v, err = verify.NewVerifier(); err != nil {
			return nil, fromVerify(err)
		}
	}
	if err := v.CheckRepoVerifiability(c.Repo); err != nil {
		return nil, fromVerify(err)
	}
	return &Enclave{host: c.Host, repo: c.Repo, relay: c.Relay, verifier: v, check: c.VerificationCheck}, nil
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

// Repo returns the trusted repository or registry reference, including version and digest pins.
func (e *Enclave) Repo() string {
	return e.repo
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
		if err == nil && !time.Now().Before(verified.FreshnessExpiresAt()) {
			err = &AttestationError{Err: ErrFreshnessExpired}
		}
		if err == nil {
			err = e.checkVerification(verified)
		}
		if attempt == retries || !retryableVerification(err) {
			break
		}
		firstErr = err
		time.Sleep(verificationRetryDelay)
	}
	if err != nil {
		if firstErr != nil {
			err = errors.Join(err, firstErr)
		}
		return nil, err
	}
	return verified, nil
}

func (e *Enclave) fetchVerification() (*verify.Verification, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	// A verification can serve many waiting requests, so no single caller's
	// context applies; fetch.Document still caps the request's duration.
	docBytes, err := fetch.Document(context.Background(), e.host, e.relay, nonce)
	if err != nil {
		return nil, err
	}

	verified, err := e.verifier.VerifyV3(docBytes, nonce, e.repo)
	if err != nil {
		return nil, fromVerify(err)
	}
	if err := validateTransportKeys(verified); err != nil {
		return nil, err
	}
	return verified, nil
}

// checkVerification runs the caller's VerificationCheck on a copy of v.
func (e *Enclave) checkVerification(v *verify.Verification) error {
	if e.check == nil {
		return nil
	}
	if err := e.check(Detached(v)); err != nil {
		return &AttestationError{Err: &rejectedError{host: e.host, err: err}}
	}
	return nil
}

// validateTransportKeys requires the keys a transport binds traffic to: the
// TLS key, and the HPKE key when the document endorses one.
func validateTransportKeys(v *verify.Verification) error {
	if err := keyFormat(v, document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format); err != nil {
		return &AttestationError{Err: err}
	}
	if _, ok := v.TLSPublicKeyFP(); !ok {
		return &AttestationError{Err: errNoTLSKey}
	}
	if err := keyFormat(v, document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format); err != nil {
		return &AttestationError{Err: err}
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
	var config *ConfigurationError
	var rejected *rejectedError
	if errors.As(err, &config) || errors.As(err, &rejected) {
		return false
	}
	// Joined failures put the terminal cause first; earlier probes are diagnostics.
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		return len(causes) > 0 && retryableVerification(causes[0])
	}
	var fetch *NetworkError
	var attestation *AttestationError
	return errors.As(err, &fetch) || errors.As(err, &attestation)
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
