package verify

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// ReferenceSource identifies why reference values were accepted.
type ReferenceSource string

const (
	SourceEndorsement ReferenceSource = "endorsement"
	SourceEmbedded    ReferenceSource = "embedded"
	SourcePolicy      ReferenceSource = "policy"
)

// ConfigVerification describes the config bound to hardware. Caller-authorized configs
// have no endorsement reference, signing key hint, or approval time.
type ConfigVerification struct {
	Source         ReferenceSource
	Name           string
	Digest         string
	Reference      string
	SigningKeyHint string
	ApprovalTime   time.Time
}

// ArtifactVerification describes accepted reference values and their authority.
// Embedded artifacts have no authenticated commit or approval time.
type ArtifactVerification struct {
	Source       ReferenceSource
	Repo         string
	Tag          string
	Digest       string
	Name         string
	Commit       string
	ApprovalTime time.Time
}

// Verification holds the facts proven during the verification of an
// attestation document. It also contains metadata of the verification process
// injected by the verifier
type Verification struct {
	// ConfigRepo identifies the selected code or runtime, without version pins.
	// Runtime reports its source of trust for config-based verification.
	ConfigRepo      string
	CodeDigest      string
	CodeTag         string
	CodeMeasurement *measurement.Measurement
	Config          *ConfigVerification   `json:",omitempty"`
	Runtime         *ArtifactVerification `json:",omitempty"`
	Platform        *ArtifactVerification `json:",omitempty"`
	// EnclaveMeasurement carries the quote's authenticated registers,
	// proven to match the expectations.
	EnclaveMeasurement *measurement.Measurement
	// CryptoMaterial holds the endorsed key items (hash-bound into the quote).
	CryptoMaterial []document.CryptoMaterialItem
	// FreshnessExpiresAt is the earlier authenticated code/platform witness
	// deadline. Cached verification must not authorize new requests at or
	// after this time; re-verifying the same witness does not extend it.
	// It is zero when WithIgnoreFreshness skips witness verification.
	// Config verification uses the earliest nonzero config, platform, or runtime approval deadline.
	// Embedded components add no deadline; all-embedded verification returns zero.
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
// crypto_material entry). ok is false if the document endorses none.
func (v *Verification) TLSPublicKeyFP() (fp string, ok bool) {
	return v.CryptoMaterialData(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
}

// HPKEPublicKey returns the endorsed HPKE public key (the id=hpke
// crypto_material entry). ok is false if the document endorses none.
func (v *Verification) HPKEPublicKey() (key string, ok bool) {
	return v.CryptoMaterialData(document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
}

// CryptoMaterialData returns the endorsed lowercase-hex data for exactly id
// and format. ok is false if the document endorses no such item or v is nil.
// Lookup does not refresh evidence or enforce FreshnessExpiresAt.
func (v *Verification) CryptoMaterialData(id, format string) (data string, ok bool) {
	if v == nil {
		return "", false
	}
	return CryptoMaterialData(v.CryptoMaterial, id, format)
}

// CryptoMaterialData looks up exactly id and format among endorsed key items;
// ok is false if none matches. It is exported so a caller holding its own
// record of a verification reuses this lookup rather than reimplementing it.
func CryptoMaterialData(items []document.CryptoMaterialItem, id, format string) (data string, ok bool) {
	for _, item := range items {
		if item.ID == id && item.Format == format {
			return item.Data, true
		}
	}
	return "", false
}

func cloneMeasurement(value *measurement.Measurement) *measurement.Measurement {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Registers = append([]string(nil), value.Registers...)
	return &cloned
}
