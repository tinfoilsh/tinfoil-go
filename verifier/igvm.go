package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/quote"
)

// ConfigPolicy contains caller expectations; none may be learned from collateral.
type ConfigPolicy struct {
	Identity   string
	AuditScope string
	Revision   string
	Digest     string
}

func (p ConfigPolicy) Validate() error {
	if err := endorsement.ValidateIdentity(p.Identity); err != nil {
		return err
	}
	if err := endorsement.ValidateAuditScope(p.AuditScope); err != nil {
		return err
	}
	if p.Revision != "" {
		if _, _, err := endorsement.ParseName(p.Identity + "/" + p.Revision); err != nil {
			return err
		}
	}
	if p.Digest != "" {
		digest, err := hex.DecodeString(p.Digest)
		if err != nil || len(digest) != sha256.Size || strings.ToLower(p.Digest) != p.Digest {
			return fmt.Errorf("config digest pin must be lowercase SHA-256")
		}
	}
	return nil
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
func (v *Verifier) VerifyIGVM(docBytes, nonce []byte, policy ConfigPolicy) (result *Verification, err error) {
	if v == nil || v.configVerifier == nil || v.provenance == nil || v.now == nil {
		return nil, configurationError(fmt.Errorf("config verification requires independently pinned signing keys"))
	}
	if v.ignoreFreshness {
		return nil, configurationError(fmt.Errorf("IGVM verification requires config and platform freshness"))
	}
	if err := policy.Validate(); err != nil {
		return nil, configurationError(err)
	}
	defer func() { err = errs.WrapAttestation(err) }()
	doc, err := document.Parse(docBytes, nonce)
	if err != nil {
		return nil, err
	}
	now := v.now()
	config, err := doc.ConfigEndorsement()
	if err != nil {
		return nil, err
	}
	approved, err := v.configVerifier.Verify(config.Config, config.Bundle, endorsement.Policy{
		Identity: policy.Identity, AuditScope: policy.AuditScope, Revision: policy.Revision, Digest: policy.Digest,
		Now: now, MaxAge: v.freshnessMaxAge,
	})
	if err != nil {
		return nil, fmt.Errorf("verifying config approval: %w", err)
	}
	if config.Reference != approved.Reference {
		return nil, fmt.Errorf("config endorsement reference does not match the verified approval")
	}
	expectedRuntime, err := igvm.ConfigRuntime(config.Config)
	if err != nil {
		return nil, err
	}
	runtimeCollateral, err := doc.IGVMRuntime()
	if err != nil {
		return nil, err
	}
	runtime, err := v.provenance.AuthenticateRuntime(runtimeCollateral, expectedRuntime)
	if err != nil {
		return nil, err
	}
	platformCollateral, err := doc.IGVMPlatform()
	if err != nil {
		return nil, err
	}
	platform, err := v.provenance.AuthenticatePlatformEndorsements(platformCollateral.Bundle, platformCollateral.Repo, platformCollateral.Tag, platformCollateral.Digest)
	if err != nil {
		return nil, err
	}
	if platform.SubjectName != igvm.PlatformSubject {
		return nil, fmt.Errorf("IGVM requires its dedicated platform endorsement artifact")
	}
	freshness, err := doc.Freshness(document.FreshnessCollateralIDPlatform)
	if err != nil {
		return nil, err
	}
	platformApprovedAt, err := v.provenance.AuthenticateFreshness(freshness.Bundle, &platform.AuthenticatedArtifact, now, v.freshnessMaxAge)
	if err != nil {
		return nil, fmt.Errorf("verifying platform freshness: %w", err)
	}
	cpu, err := doc.CPUEndorsements()
	if err != nil {
		return nil, err
	}
	authenticated, err := quote.Authenticate(doc.CPUEvidence(), cpu, v.quoteOptions(now))
	if err != nil {
		return nil, err
	}
	configHash := sha256.Sum256(config.Config)
	assembled, err := quote.AssembleIGVM(doc, platform.Artifact, runtime.Manifest.IGVM, v.pinnedRegisters, configHash, authenticated)
	if err != nil {
		return nil, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, err
	}
	measurement, err := quote.RuntimeMeasurement(runtime.Manifest.IGVM, authenticated.Platform())
	if err != nil {
		return nil, err
	}
	return &Verification{
		CodeDigest: runtime.Digest, CodeTag: runtime.Tag, CodeMeasurement: measurement,
		EnclaveMeasurement: authenticated.Measurement, Config: approved, CryptoMaterial: doc.CryptoMaterialItems(),
		FreshnessExpiresAt: freshnessExpiration(approved.ApprovalTime, platformApprovedAt, v.freshnessMaxAge),
	}, nil
}
