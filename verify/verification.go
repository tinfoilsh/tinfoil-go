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
	// RegistryID is authenticated by the certificate, or public for legacy registry approvals.
	RegistryID    string `json:"Scope"`
	SignatureTime time.Time
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

// VerifiedFacts holds the facts proven by the verification of an attestation
// document, including the channel keys that a caller binds its traffic to.
// Only the verifier creates one, as the VerifiedFacts of a report on a
// document that it accepted, and its fields cannot be changed: accessors
// return copies. Assigning through a pointer still replaces the whole value,
// so code that keeps a VerifiedFacts hands out copies of it, as the SDK's
// clients do.
type VerifiedFacts struct {
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
}

func init() {
	verifyhook.NewVerifiedFacts = func(f verifyhook.Fields) any {
		v := &VerifiedFacts{
			configRepo:         f.ConfigRepo,
			codeDigest:         f.CodeDigest,
			codeTag:            f.CodeTag,
			enclaveMeasurement: f.EnclaveMeasurement,
			cryptoMaterial:     slices.Clone(f.CryptoMaterial),
			freshnessExpiresAt: f.FreshnessExpiresAt,
		}
		if f.CodeMeasurement != nil {
			v.codeMeasurement = f.CodeMeasurement.Clone()
		}
		if config, ok := f.Config.(*ConfigVerification); ok && config != nil {
			copied := *config
			v.config = &copied
		}
		if runtime, ok := f.Runtime.(*ArtifactVerification); ok && runtime != nil {
			copied := *runtime
			v.runtime = &copied
		}
		if platform, ok := f.Platform.(*ArtifactVerification); ok && platform != nil {
			copied := *platform
			v.platform = &copied
		}
		return v
	}
}

// ConfigRepo identifies the selected code or runtime, without version pins.
// Runtime reports its source of trust for config-based verification.
func (v *VerifiedFacts) ConfigRepo() string { return v.configRepo }

// CodeDigest is the digest of the verified code or runtime artifact.
func (v *VerifiedFacts) CodeDigest() string { return v.codeDigest }

// CodeTag is the release tag of the verified code or runtime artifact.
func (v *VerifiedFacts) CodeTag() string { return v.codeTag }

// CodeMeasurement returns the registers the release fixes on the enclave's
// platform: an ExpectedSEVSNP or ExpectedTDX, with nil for a register the
// release leaves to the platform.
func (v *VerifiedFacts) CodeMeasurement() measurement.Expected {
	if v.codeMeasurement == nil {
		return nil
	}
	return v.codeMeasurement.Clone()
}

// Config describes the config bound to hardware. ok is false for
// verification against a code release, which has no config.
func (v *VerifiedFacts) Config() (config ConfigVerification, ok bool) {
	if v.config == nil {
		return ConfigVerification{}, false
	}
	return *v.config, true
}

// Runtime describes the runtime a config-based verification accepted. ok is
// false for verification against a code release.
func (v *VerifiedFacts) Runtime() (runtime ArtifactVerification, ok bool) {
	if v.runtime == nil {
		return ArtifactVerification{}, false
	}
	return *v.runtime, true
}

// Platform describes the platform endorsements a config-based verification
// accepted. ok is false for verification against a code release.
func (v *VerifiedFacts) Platform() (platform ArtifactVerification, ok bool) {
	if v.platform == nil {
		return ArtifactVerification{}, false
	}
	return *v.platform, true
}

// EnclaveMeasurement returns the quote's authenticated registers, proven to
// match the expectations: an SEVSNP or TDX.
func (v *VerifiedFacts) EnclaveMeasurement() measurement.Measurement { return v.enclaveMeasurement }

// CryptoMaterial returns a copy of the endorsed key items, which are
// hash-bound into the quote.
func (v *VerifiedFacts) CryptoMaterial() []document.CryptoMaterialItem {
	return slices.Clone(v.cryptoMaterial)
}

// FreshnessExpiresAt is the earliest authenticated approval or CPU collateral
// deadline. Cached verification must not authorize new requests at or after
// this time; re-verifying unchanged material does not extend it. Short-lived
// signing certificates are checked at the authenticated signature timestamp; their
// historical validity does not add an approval deadline. Embedded reference
// values add no deadline; hardware collateral still bounds the result.
func (v *VerifiedFacts) FreshnessExpiresAt() time.Time { return v.freshnessExpiresAt }

// VerificationMetadata describes how a verification was performed. The
// verifier and the client that called it fill it in from their own state;
// none of it is attested by or checked against the document.
type VerificationMetadata struct {
	// Verifier identifies the SDK that performed the verification.
	Verifier SoftwareIdentity
	// VerifiedAt is the instant that the document was appraised at: read once from
	// the local clock by VerifyV3, or the caller's verificationTime for
	// VerifyV3At. It is not a freshness guarantee.
	VerifiedAt time.Time
	// Host is the enclave that the client contacted for the document, a host
	// with an optional port: for a router client the router that it chose, and
	// for a gateway client the replica. It is what the client connected to, not
	// an attested fact, so it proves nothing about the enclave. The verifier
	// doesn't know the host and leaves Host empty; the clients set it on every
	// report that they produce, and a caller that calls the verifier itself
	// can set it on the report that it gets.
	Host string
}

// SoftwareIdentity identifies software involved in verification.
type SoftwareIdentity struct {
	Name    string
	Version string
}

// TLSPublicKeyFP returns the endorsed TLS key fingerprint: the id=tls
// crypto_material entry in KeySPKIFPSHA256V1Format. ok is false if the
// document endorses no such entry, including a tls entry in another format.
func (v *VerifiedFacts) TLSPublicKeyFP() (fp string, ok bool) {
	return v.CryptoMaterialData(document.CryptoMaterialIDTLS, document.KeySPKIFPSHA256V1Format)
}

// HPKEPublicKey returns the endorsed HPKE public key: the id=hpke
// crypto_material entry in KeyX25519HPKEV1Format. ok is false if the
// document endorses no such entry, including an hpke entry in another format.
func (v *VerifiedFacts) HPKEPublicKey() (key string, ok bool) {
	return v.CryptoMaterialData(document.CryptoMaterialIDHPKE, document.KeyX25519HPKEV1Format)
}

// CryptoMaterialData returns the endorsed lowercase-hex data for exactly id
// and format. ok is false if the document endorses no such item or v is nil.
// Lookup does not refresh evidence or enforce FreshnessExpiresAt.
func (v *VerifiedFacts) CryptoMaterialData(id, format string) (data string, ok bool) {
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
