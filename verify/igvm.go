package verify

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

// ConfigPolicy contains caller expectations; none may be learned from collateral.
type ConfigPolicy struct {
	Identity   string
	AuditScope string
	Revision   string
	Digest     string
}

func (p ConfigPolicy) Validate() error {
	return (endorsement.Policy{
		Identity: p.Identity, AuditScope: p.AuditScope, Revision: p.Revision, Digest: p.Digest,
	}).ValidatePins()
}

// WithConfigSigningKeys pins the keys and scopes allowed to approve configs.
func WithConfigSigningKeys(keys []endorsement.SigningKey) Option {
	return func(v *Verifier) error {
		if len(keys) == 0 {
			return fmt.Errorf("config signing keys must not be empty")
		}
		v.configKeys = append([]endorsement.SigningKey(nil), keys...)
		return nil
	}
}

// WithFreshnessSigningKeys pins Tinfoil's platform and runtime approval keys.
// These keys do not authorize configs for any org.
func WithFreshnessSigningKeys(keys []crypto.PublicKey) Option {
	return func(v *Verifier) error {
		if len(keys) == 0 {
			return fmt.Errorf("freshness signing keys must not be empty")
		}
		v.freshnessKeys = append([]crypto.PublicKey(nil), keys...)
		return nil
	}
}

// VerifyIGVM verifies the config-binding profile without falling back to legacy
// repository verification. Config, platform, and runtime approvals must be fresh.
func (v *Verifier) VerifyIGVM(docBytes, nonce []byte, policy ConfigPolicy) (*Verification, error) {
	verified, _, err := v.verifyIGVM(docBytes, nonce, policy)
	return verified, err
}

func (v *Verifier) verifyIGVM(docBytes, nonce []byte, policy ConfigPolicy) (result *Verification, failed layer, err error) {
	if v == nil || v.configVerifier == nil || v.freshnessVerifier == nil || v.provenance == nil || v.now == nil {
		return nil, layerNone, configurationError(fmt.Errorf("config verification requires independently pinned signing keys for configs and freshness"))
	}
	if v.ignoreFreshness {
		return nil, layerNone, configurationError(fmt.Errorf("IGVM verification requires config, platform, and runtime freshness"))
	}
	if err := policy.Validate(); err != nil {
		return nil, layerProvenance, configurationError(err)
	}
	defer func() { err = errs.WrapAttestation(err) }()
	doc, err := document.Parse(docBytes, nonce)
	if err != nil {
		return nil, layerEnvelope, err
	}
	now := v.now()
	config, err := doc.ConfigEndorsement()
	if err != nil {
		return nil, layerProvenance, err
	}
	approved, err := v.configVerifier.Verify(config.Config, config.Bundle, endorsement.Policy{
		Identity: policy.Identity, AuditScope: policy.AuditScope, Revision: policy.Revision, Digest: policy.Digest,
		Now: now, MaxAge: v.freshnessMaxAge,
	})
	if err != nil {
		return nil, layerProvenance, fmt.Errorf("verifying config approval: %w", err)
	}
	if config.Reference != approved.Reference {
		return nil, layerProvenance, fmt.Errorf("config endorsement reference does not match the verified approval")
	}
	expectedRuntime, err := igvm.ConfigRuntime(config.Config)
	if err != nil {
		return nil, layerProvenance, err
	}
	runtimeCollateral, err := doc.IGVMRuntime()
	if err != nil {
		return nil, layerProvenance, err
	}
	runtime, err := v.provenance.AuthenticateRuntime(runtimeCollateral, expectedRuntime)
	if err != nil {
		return nil, layerProvenance, err
	}
	platformCollateral, err := doc.IGVMPlatform()
	if err != nil {
		return nil, layerProvenance, err
	}
	platform, err := v.provenance.AuthenticatePlatformEndorsements(platformCollateral.Bundle, platformCollateral.Repo, platformCollateral.Tag, platformCollateral.Digest)
	if err != nil {
		return nil, layerProvenance, err
	}
	if platform.SubjectName != igvm.PlatformSubject {
		return nil, layerProvenance, fmt.Errorf("IGVM requires its dedicated platform endorsement artifact")
	}
	platformApprovedAt, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDPlatform, freshness.KindPlatform, &platform.AuthenticatedArtifact, now)
	if err != nil {
		return nil, layerProvenance, fmt.Errorf("verifying platform freshness: %w", err)
	}
	runtimeApprovedAt, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDRuntime, freshness.KindRuntime, &runtime.AuthenticatedArtifact, now)
	if err != nil {
		return nil, layerProvenance, fmt.Errorf("verifying runtime freshness: %w", err)
	}
	authenticated, err := quote.Authenticate(doc.CPUEvidence(), doc.CPUEndorsements(), v.quoteOptions(now))
	if err != nil {
		return nil, layerQuote, err
	}
	configHash := sha256.Sum256(config.Config)
	assembled, err := quote.AssembleIGVM(doc, platform.Artifact, runtime.Manifest.IGVM, v.pinnedRegisters, configHash, authenticated)
	if err != nil {
		return nil, layerPolicy, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, layerPolicy, err
	}
	measurement, err := quote.RuntimeMeasurement(runtime.Manifest.IGVM, authenticated.Platform())
	if err != nil {
		return nil, layerPolicy, err
	}
	return &Verification{
		ConfigRepo: runtime.Repo, CodeDigest: runtime.Digest, CodeTag: runtime.Tag, CodeMeasurement: measurement,
		EnclaveMeasurement: authenticated.Measurement, Config: approved, CryptoMaterial: doc.CryptoMaterialItems(),
		FreshnessExpiresAt: igvmFreshnessExpiration(approved.ApprovalTime, platformApprovedAt, runtimeApprovedAt, v.freshnessMaxAge),
		Metadata:           VerificationMetadata{Verifier: v.identity, VerifiedAt: now},
	}, layerNone, nil
}

func (v *Verifier) authenticateArtifactFreshness(doc *document.Document, id, kind string, artifact *provenance.AuthenticatedArtifact, now time.Time) (time.Time, error) {
	material, err := doc.Freshness(id)
	if err != nil {
		return time.Time{}, err
	}
	if material.Format != collateral.ArtifactFreshnessV1Format {
		return time.Time{}, fmt.Errorf("IGVM requires Tinfoil artifact freshness approvals")
	}
	approved, err := v.freshnessVerifier.Verify(material.Bundle, freshness.Policy{
		Artifact: freshness.Artifact{Kind: kind, Repo: artifact.Repo, Tag: artifact.Tag, Name: artifact.SubjectName, Digest: artifact.Digest},
		Now:      now, MaxAge: v.freshnessMaxAge,
	})
	if err != nil {
		return time.Time{}, err
	}
	return approved.ApprovalTime, nil
}

func igvmFreshnessExpiration(config, platform, runtime time.Time, maxAge time.Duration) time.Time {
	earliest := config
	if platform.Before(earliest) {
		earliest = platform
	}
	if runtime.Before(earliest) {
		earliest = runtime
	}
	return earliest.Add(maxAge)
}
