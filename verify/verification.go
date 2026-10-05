package verify

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Verification holds the facts proven during the verification of an
// attestation document. It also contains metadata of the verification process
// injected by the verifier
type Verification struct {
	// ConfigRepo is the repository the code provenance was authenticated
	// against, without a tag or digest.
	ConfigRepo      string
	CodeDigest      string
	CodeTag         string
	CodeMeasurement *measurement.Measurement
	Config          *endorsement.Verified `json:",omitempty"`
	// EnclaveMeasurement carries the quote's authenticated registers,
	// proven to match the expectations.
	EnclaveMeasurement *measurement.Measurement
	// CryptoMaterial holds the endorsed key items (hash-bound into the quote).
	CryptoMaterial []document.CryptoMaterialItem
	// FreshnessExpiresAt is the earlier authenticated code/platform witness
	// deadline. Cached verification must not authorize new requests at or
	// after this time; re-verifying the same witness does not extend it.
	// It is zero when WithIgnoreFreshness skips witness verification.
	// IGVM uses the config approval and platform witness deadlines.
	FreshnessExpiresAt time.Time
	// Metadata describes the verification rather than the document.
	Metadata VerificationMetadata
}

// VerificationMetadata describes how a verification was performed. The
// verifier fills it in from its own state; none of it is attested by or
// checked against the document.
type VerificationMetadata struct {
	// Verifier identifies the SDK that performed the verification.
	Verifier SoftwareIdentity
	// VerifiedAt is the instant the document was appraised at, read once from
	// the local clock. It is not a freshness guarantee.
	VerifiedAt time.Time
}

// SoftwareIdentity identifies software involved in verification.
type SoftwareIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// TLSPublicKeyFP returns the endorsed TLS key fingerprint (the id=tls
// crypto_material entry), or an error if the document does not endorse one.
func (v *Verification) TLSPublicKeyFP() (string, error) {
	return v.CryptoMaterialData(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
}

// HPKEPublicKey returns the endorsed HPKE public key (the id=hpke
// crypto_material entry), or an error if the document does not endorse one.
func (v *Verification) HPKEPublicKey() (string, error) {
	return v.CryptoMaterialData(document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
}

// CryptoMaterialData returns the endorsed lowercase-hex data for exactly id and
// format. Lookup does not refresh evidence or enforce FreshnessExpiresAt.
func (v *Verification) CryptoMaterialData(id, format string) (string, error) {
	if v == nil {
		return "", &errs.ConfigurationError{Err: fmt.Errorf("verification is required")}
	}
	return CryptoMaterialData(v.CryptoMaterial, id, format)
}

// CryptoMaterialData looks up exactly id and format among endorsed key items.
// It is exported so a caller holding its own record of a verification reuses
// this lookup rather than reimplementing it.
func CryptoMaterialData(items []document.CryptoMaterialItem, id, format string) (string, error) {
	for _, item := range items {
		if item.ID != id {
			continue
		}
		if item.Format != format {
			return "", &errs.AttestationError{Err: fmt.Errorf("crypto_material item %q has format %q, want %q", id, item.Format, format)}
		}
		return item.Data, nil
	}
	return "", &errs.AttestationError{Err: fmt.Errorf("document endorses no %q crypto material", id)}
}

func cloneMeasurement(value *measurement.Measurement) *measurement.Measurement {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Registers = append([]string(nil), value.Registers...)
	return &cloned
}
