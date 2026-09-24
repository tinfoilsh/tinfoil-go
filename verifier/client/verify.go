package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

// VerifiedDocumentV3 contains verified measurements, transport keys, and witness expiry.
type VerifiedDocumentV3 struct {
	ConfigRepo      string
	EnclaveHost     string
	Verifier        SoftwareIdentity
	VerifiedAt      string
	CodeDigest      string
	CodeTag         string
	CodeMeasurement *measurement.Measurement
	// EnclaveMeasurement carries the quote's authenticated registers,
	// proven to match the expectations.
	EnclaveMeasurement *measurement.Measurement
	// CryptoMaterial holds the endorsed key items (hash-bound into the quote).
	CryptoMaterial []document.CryptoMaterialItem
	// FreshnessExpiresAt is the earlier authenticated code/platform witness
	// deadline. Cached verification must not authorize new requests at or
	// after this time; re-verifying the same witness does not extend it.
	FreshnessExpiresAt time.Time
}

// TLSPublicKeyFP returns the endorsed TLS key fingerprint (the id=tls
// crypto_material entry), or an error if the document does not endorse one.
func (v *VerifiedDocumentV3) TLSPublicKeyFP() (string, error) {
	return v.CryptoMaterialData(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
}

// HPKEPublicKey returns the endorsed HPKE public key (the id=hpke
// crypto_material entry), or an error if the document does not endorse one.
func (v *VerifiedDocumentV3) HPKEPublicKey() (string, error) {
	return v.CryptoMaterialData(document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
}

// CryptoMaterialData returns the endorsed lowercase-hex data for exactly id and
// format. Lookup does not refresh evidence or enforce FreshnessExpiresAt.
func (v *VerifiedDocumentV3) CryptoMaterialData(id, format string) (string, error) {
	if v == nil {
		return "", &ConfigurationError{Err: fmt.Errorf("verified document is required")}
	}
	return verifier.CryptoMaterialData(v.CryptoMaterial, id, format)
}

func (v *VerifiedDocumentV3) validateTransportKeys() error {
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

// VerifyDocumentV3 verifies a nonce-bound document with the supplied policy.
// A nil policy uses defaults. repo is a trusted owner/name[@tag][@sha256:digest].
// Callers must bind traffic to the returned keys and enforce FreshnessExpiresAt.
//
// Go callers should prefer verifier.Verifier, which this wraps: it takes
// functional options rather than the struct the Swift bindings need, and
// returns only what the document proved. This entry point stays for the
// gomobile surface, which cannot express either, and for callers already
// built on it.
func VerifyDocumentV3(docBytes, nonce []byte, repo string, opts *VerificationOptions) (*VerifiedDocumentV3, error) {
	core, err := opts.verifier()
	if err != nil {
		return nil, err
	}
	verified, err := core.VerifyV3(docBytes, nonce, repo)
	if err != nil {
		return nil, err
	}
	return fromVerification(verified), nil
}

// fromVerification copies what the document proved. The fields describing the
// act of verifying — ConfigRepo, EnclaveHost, Verifier, VerifiedAt — are left
// unset; fetchVerification fills them, and VerifyDocumentV3 leaves them empty
// because it contacts no enclave.
func fromVerification(v *verifier.Verification) *VerifiedDocumentV3 {
	return &VerifiedDocumentV3{
		CodeDigest:         v.CodeDigest,
		CodeTag:            v.CodeTag,
		CodeMeasurement:    v.CodeMeasurement,
		EnclaveMeasurement: v.EnclaveMeasurement,
		CryptoMaterial:     v.CryptoMaterial,
		FreshnessExpiresAt: v.FreshnessExpiresAt,
	}
}

func (s *SecureClient) fetchVerification() (*VerifiedDocumentV3, error) {
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	docBytes, err := document.FetchVia(s.enclave, s.relay, nonce)
	if err != nil {
		return nil, err
	}

	core, err := s.core.VerifyV3(docBytes, nonce, s.repo)
	if err != nil {
		return nil, err
	}
	verified := fromVerification(core)

	if err := verified.validateTransportKeys(); err != nil {
		return nil, err
	}
	verified.ConfigRepo, _, _ = strings.Cut(s.repo, "@")
	verified.EnclaveHost = s.enclave
	verified.Verifier = currentVerifierIdentity()
	verified.VerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return verified, nil
}

// Verify refreshes the client's verified measurements and keys.
func (s *SecureClient) Verify() (*VerifiedDocumentV3, error) {
	state, err := s.verifiedState(context.Background(), nil, true)
	if err != nil {
		return nil, err
	}
	return cloneVerification(state.VerifiedDocumentV3), nil
}
