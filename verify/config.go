package verify

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

// ConfigPolicy contains caller expectations; none may be learned from collateral.
type ConfigPolicy struct {
	Identity string
	Revision string
	Digest   string
}

func (p ConfigPolicy) Validate() error {
	return (endorsement.ConfigPolicy{
		Identity: p.Identity, Revision: p.Revision, Digest: p.Digest,
	}).ValidatePins()
}

// WithConfigSigningKeys replaces public config trust with the supplied keys.
// These keys define the accepted audit scope and do not authorize artifact freshness.
func WithConfigSigningKeys(keys []crypto.PublicKey) Option {
	return func(v *Verifier) error {
		if len(keys) == 0 {
			return fmt.Errorf("config signing keys must not be empty")
		}
		v.configKeys = append([]crypto.PublicKey(nil), keys...)
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

// VerifyConfig verifies the config-binding profile without falling back to legacy
// repository verification. Config, platform, and runtime approvals must be fresh.
func (v *Verifier) VerifyConfig(docBytes, nonce []byte, policy ConfigPolicy) (*Verification, error) {
	verified, _, err := v.verifyConfig(docBytes, nonce, policy)
	return verified, err
}

func (v *Verifier) verifyConfig(docBytes, nonce []byte, policy ConfigPolicy) (*Verification, layer, error) {
	if v == nil || v.configVerifier == nil || v.freshnessVerifier == nil || v.endorsements == nil || v.now == nil {
		return nil, layerNone, configurationError(fmt.Errorf("uninitialized config verifier"))
	}
	if v.ignoreFreshness {
		return nil, layerNone, configurationError(fmt.Errorf("config verification requires config, platform, and runtime freshness"))
	}
	if err := policy.Validate(); err != nil {
		return nil, layerProvenance, configurationError(err)
	}
	return v.verify(docBytes, nonce, func(doc *document.Document, now time.Time) (*referenceValues, error) {
		return v.configReferences(doc, policy, now)
	})
}

func (v *Verifier) configReferences(doc *document.Document, policy ConfigPolicy, now time.Time) (*referenceValues, error) {
	config, err := doc.ConfigEndorsement()
	if err != nil {
		return nil, err
	}
	approved, err := v.configVerifier.Verify(config.Config, config.Bundle, endorsement.ConfigPolicy{
		Identity: policy.Identity, Revision: policy.Revision, Digest: policy.Digest,
		Now: now, MaxAge: v.freshnessMaxAge,
	})
	if err != nil {
		return nil, fmt.Errorf("verifying config approval: %w", err)
	}
	if config.Reference != approved.Reference {
		return nil, fmt.Errorf("config endorsement reference does not match the verified approval")
	}
	expectedRuntime, err := runtime.ConfigRuntime(config.Config)
	if err != nil {
		return nil, err
	}
	runtimeCollateral, err := doc.Runtime()
	if err != nil {
		return nil, err
	}
	authenticatedRuntime, err := v.endorsements.AuthenticateRuntime(runtimeCollateral, expectedRuntime)
	if err != nil {
		return nil, err
	}
	platformCollateral, err := doc.ConfigPlatform()
	if err != nil {
		return nil, err
	}
	platform, err := v.endorsements.AuthenticatePlatformEndorsements(platformCollateral.Bundle, platformCollateral.Repo, platformCollateral.Tag, platformCollateral.Digest)
	if err != nil {
		return nil, err
	}
	if platform.SubjectName != runtime.PlatformSubject {
		return nil, fmt.Errorf("config verification requires its dedicated platform endorsement artifact")
	}
	platformApprovedAt, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDPlatform, freshness.KindPlatform, &platform.AuthenticatedArtifact, now)
	if err != nil {
		return nil, fmt.Errorf("verifying platform freshness: %w", err)
	}
	runtimeApprovedAt, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDRuntime, freshness.KindRuntime, &authenticatedRuntime.AuthenticatedArtifact, now)
	if err != nil {
		return nil, fmt.Errorf("verifying runtime freshness: %w", err)
	}
	return &referenceValues{
		quote: quote.ConfigReferenceValues{
			Endorsements: platform.Artifact,
			Runtime:      authenticatedRuntime.Manifest.Measurements,
			Hash:         sha256.Sum256(config.Config),
		},
		artifact:           authenticatedRuntime.AuthenticatedArtifact,
		config:             approved,
		freshnessExpiresAt: freshnessExpiration(v.freshnessMaxAge, approved.ApprovalTime, platformApprovedAt, runtimeApprovedAt),
	}, nil
}

func (v *Verifier) authenticateArtifactFreshness(doc *document.Document, id, kind string, artifact *endorsement.AuthenticatedArtifact, now time.Time) (time.Time, error) {
	material, err := doc.Freshness(id)
	if err != nil {
		return time.Time{}, err
	}
	if material.Format != collateral.ArtifactFreshnessV1Format {
		return time.Time{}, fmt.Errorf("config verification requires Tinfoil artifact freshness approvals")
	}
	approved, err := v.freshnessVerifier.Verify(material.Bundle, endorsement.FreshnessPolicy{
		Artifact: freshness.Artifact{Kind: kind, Repo: artifact.Repo, Tag: artifact.Tag, Name: artifact.SubjectName, Digest: artifact.Digest},
		Now:      now, MaxAge: v.freshnessMaxAge,
	})
	if err != nil {
		return time.Time{}, err
	}
	return approved.ApprovalTime, nil
}
