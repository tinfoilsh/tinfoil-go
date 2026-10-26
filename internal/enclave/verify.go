package enclave

import (
	"context"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// errNoTLSKey reports a verification with no TLS key to bind a channel to.
var errNoTLSKey = fmt.Errorf("document endorses no %q key", document.CryptoMaterialIDTLS)

// validateTransportKeys requires the keys a Handle binds traffic to: the
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

func (s *Handle) fetchVerification() (*verify.Verification, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	// One refresh serves every waiting request, so no single caller's context
	// applies; fetch.Document still caps the request's duration.
	docBytes, err := fetch.Document(context.Background(), s.enclave, s.relay, nonce)
	if err != nil {
		return nil, err
	}

	verified, err := s.verifier.VerifyV3(docBytes, nonce, s.repo)
	if err != nil {
		return nil, fromVerify(err)
	}
	if err := validateTransportKeys(verified); err != nil {
		return nil, err
	}
	return verified, nil
}

// Verify refreshes the client's verified measurements and keys.
func (s *Handle) Verify() (*verify.Verification, error) {
	return s.Reverify(context.Background())
}

// EnsureVerified returns a verification that is valid now, verifying first
// only if the cached one has expired or been rejected. Concurrent callers
// share one verification.
func (s *Handle) EnsureVerified(ctx context.Context) (*verify.Verification, error) {
	state, err := s.verifiedState(ctx, false, verificationRetries)
	if err != nil {
		return nil, err
	}
	return detached(state.Verification), nil
}

// Reverify verifies again even if the cached verification is still valid.
func (s *Handle) Reverify(ctx context.Context) (*verify.Verification, error) {
	state, err := s.verifiedState(ctx, true, verificationRetries)
	if err != nil {
		return nil, err
	}
	return detached(state.Verification), nil
}

// detached returns a copy of v for a caller to keep. Its fields cannot be
// changed, but a caller holding a pointer can replace the whole value, so the
// handle never hands out the one it caches. The copy shares v's internals,
// which only copying accessors can reach.
func detached(v *verify.Verification) *verify.Verification {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}
