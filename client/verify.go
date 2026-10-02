package client

import (
	"context"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// validateTransportKeys requires the keys a SecureClient binds traffic to: the
// TLS key, and the HPKE key when the document endorses one.
func validateTransportKeys(v *verify.Verification) error {
	if _, err := v.TLSPublicKeyFP(); err != nil {
		return err
	}
	for _, item := range v.CryptoMaterial {
		if item.ID == document.CryptoMaterialIDHPKE {
			_, err := v.HPKEPublicKey()
			return err
		}
	}
	return nil
}

func (s *SecureClient) fetchVerification() (*verify.Verification, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	docBytes, err := fetch.Document(s.enclave, s.relay, nonce)
	if err != nil {
		return nil, err
	}

	verified, err := s.verifier.VerifyV3(docBytes, nonce, s.repo)
	if err != nil {
		return nil, err
	}
	if err := validateTransportKeys(verified); err != nil {
		return nil, err
	}
	return verified, nil
}

// Verify refreshes the client's verified measurements and keys.
func (s *SecureClient) Verify() (*verify.Verification, error) {
	state, err := s.verifiedState(context.Background(), true, verificationRetries)
	if err != nil {
		return nil, err
	}
	return cloneVerification(state.Verification), nil
}
