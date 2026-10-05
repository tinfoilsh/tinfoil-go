package verify

import (
	"crypto/sha256"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/igvm"
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

// VerifyIGVM verifies the config-binding profile without falling back to legacy
// repository verification. Config freshness authorizes its pinned runtime;
// platform freshness is required independently.
func (v *Verifier) VerifyIGVM(docBytes, nonce []byte, policy ConfigPolicy) (*Verification, error) {
	verified, _, err := v.verifyIGVM(docBytes, nonce, policy)
	return verified, err
}

func (v *Verifier) verifyIGVM(docBytes, nonce []byte, policy ConfigPolicy) (result *Verification, failed layer, err error) {
	if v == nil || v.configVerifier == nil || v.provenance == nil || v.now == nil {
		return nil, layerNone, configurationError(fmt.Errorf("config verification requires independently pinned signing keys"))
	}
	if v.ignoreFreshness {
		return nil, layerNone, configurationError(fmt.Errorf("IGVM verification requires config and platform freshness"))
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
	platformApprovedAt, err := v.authenticateFreshness(doc, collateral.FreshnessIDPlatform, &platform.AuthenticatedArtifact, now)
	if err != nil {
		return nil, layerProvenance, fmt.Errorf("verifying platform freshness: %w", err)
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
		FreshnessExpiresAt: freshnessExpiration(approved.ApprovalTime, platformApprovedAt, v.freshnessMaxAge),
		Metadata:           VerificationMetadata{Verifier: v.identity, VerifiedAt: now},
	}, layerNone, nil
}
