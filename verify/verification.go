package verify

import (
	"slices"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/verifyhook"
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
// attestation document, and metadata the verifier adds about the verification
// itself. Only the verifier creates one, and its fields cannot be changed:
// accessors return copies. Assigning through a pointer still replaces the whole
// value, so code that keeps a Verification hands out copies of it, as
// enclave.Handle does.
type Verification struct {
	configRepo         string
	codeDigest         string
	codeTag            string
	codeMeasurement    measurement.Expected
	config             *ConfigVerification
	runtime            *ArtifactVerification
	platform           *ArtifactVerification
	enclaveMeasurement measurement.Measurement
	cryptoMaterial     []document.CryptoMaterialItem
	freshnessExpiresAt time.Time
	metadata           VerificationMetadata
}

func init() {
	verifyhook.NewVerification = func(f verifyhook.Fields) any {
		v := &Verification{
			configRepo:         f.ConfigRepo,
			codeDigest:         f.CodeDigest,
			codeTag:            f.CodeTag,
			enclaveMeasurement: f.EnclaveMeasurement,
			cryptoMaterial:     slices.Clone(f.CryptoMaterial),
			freshnessExpiresAt: f.FreshnessExpiresAt,
			metadata: VerificationMetadata{
				Verifier:   SoftwareIdentity{Name: f.VerifierName, Version: f.VerifierVersion},
				VerifiedAt: f.VerifiedAt,
			},
		}
		if f.CodeMeasurement != nil {
			v.codeMeasurement = f.CodeMeasurement.Clone()
		}
		return v
	}
}

// ConfigRepo identifies the selected code or runtime, without version pins.
// Runtime reports its source of trust for config-based verification.
func (v *Verification) ConfigRepo() string { return v.configRepo }

// CodeDigest is the digest of the verified code or runtime artifact.
func (v *Verification) CodeDigest() string { return v.codeDigest }

// CodeTag is the release tag of the verified code or runtime artifact.
func (v *Verification) CodeTag() string { return v.codeTag }

// CodeMeasurement returns the registers the release fixes on the enclave's
// platform: an ExpectedSEVSNP or ExpectedTDX, with nil for a register the
// release leaves to the platform.
func (v *Verification) CodeMeasurement() measurement.Expected {
	if v.codeMeasurement == nil {
		return nil
	}
	return v.codeMeasurement.Clone()
}

// Config describes the config bound to hardware. ok is false for
// verification against a code release, which has no config.
func (v *Verification) Config() (config ConfigVerification, ok bool) {
	if v.config == nil {
		return ConfigVerification{}, false
	}
	return *v.config, true
}

// Runtime describes the runtime a config-based verification accepted. ok is
// false for verification against a code release.
func (v *Verification) Runtime() (runtime ArtifactVerification, ok bool) {
	if v.runtime == nil {
		return ArtifactVerification{}, false
	}
	return *v.runtime, true
}

// Platform describes the platform endorsements a config-based verification
// accepted. ok is false for verification against a code release.
func (v *Verification) Platform() (platform ArtifactVerification, ok bool) {
	if v.platform == nil {
		return ArtifactVerification{}, false
	}
	return *v.platform, true
}

// EnclaveMeasurement returns the quote's authenticated registers, proven to
// match the expectations: an SEVSNP or TDX.
func (v *Verification) EnclaveMeasurement() measurement.Measurement { return v.enclaveMeasurement }

// CryptoMaterial returns a copy of the endorsed key items, which are
// hash-bound into the quote.
func (v *Verification) CryptoMaterial() []document.CryptoMaterialItem {
	return slices.Clone(v.cryptoMaterial)
}

// FreshnessExpiresAt is the earlier authenticated code/platform witness
// deadline. Cached verification must not authorize new requests at or after
// this time; re-verifying the same witness does not extend it. Config
// verification uses the earliest nonzero config, platform, or runtime approval
// deadline. Embedded components add no deadline; all-embedded verification
// returns zero.
func (v *Verification) FreshnessExpiresAt() time.Time { return v.freshnessExpiresAt }

// Metadata describes the verification rather than the document.
func (v *Verification) Metadata() VerificationMetadata { return v.metadata }

// VerificationMetadata describes how a verification was performed. The
// verifier fills it in from its own state; none of it is attested by or
// checked against the document.
type VerificationMetadata struct {
	// Verifier identifies the SDK that performed the verification.
	Verifier SoftwareIdentity
	// VerifiedAt is the instant the document was appraised at: read once from
	// the local clock by VerifyV3, or the caller's verificationTime for
	// VerifyV3At. It is not a freshness guarantee.
	VerifiedAt time.Time
}

// SoftwareIdentity identifies software involved in verification.
type SoftwareIdentity struct {
	Name    string
	Version string
}

// TLSPublicKeyFP returns the endorsed TLS key fingerprint: the id=tls
// crypto_material entry in KeySPKIFPSHA256V1Format. ok is false if the
// document endorses no such entry, including a tls entry in another format.
func (v *Verification) TLSPublicKeyFP() (fp string, ok bool) {
	return v.CryptoMaterialData(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
}

// HPKEPublicKey returns the endorsed HPKE public key: the id=hpke
// crypto_material entry in KeyX25519HPKEV1Format. ok is false if the
// document endorses no such entry, including an hpke entry in another format.
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
	return CryptoMaterialData(v.cryptoMaterial, id, format)
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
