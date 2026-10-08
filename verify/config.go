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

// ParseConfigReference validates org/project[@revision][@sha256:digest] and
// returns the canonical /org/project identity and optional pins.
func ParseConfigReference(ref string) (identity, revision, digest string, err error) {
	repo, revision, digest, err := ParseReference(ref)
	if err != nil {
		return "", "", "", err
	}
	policy := endorsement.ConfigPolicy{Identity: "/" + repo, Revision: revision, Digest: digest}
	return policy.Identity, revision, digest, policy.ValidatePins()
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
// ref is the caller's expected org/project[@revision][@sha256:digest].
func (v *Verifier) VerifyConfig(docBytes, nonce []byte, ref string) (*Verification, error) {
	if v == nil || v.configVerifier == nil || v.freshnessVerifier == nil || v.endorsements == nil || v.now == nil {
		return nil, configurationError(fmt.Errorf("uninitialized config verifier"))
	}
	if v.ignoreFreshness {
		return nil, configurationError(fmt.Errorf("config verification requires config, platform, and runtime freshness"))
	}
	identity, revision, digest, err := ParseConfigReference(ref)
	if err != nil {
		return nil, configurationError(err)
	}
	verified, _, err := v.verify(docBytes, nonce, func(doc *document.Document, now time.Time) (*referenceValues, error) {
		return v.configReferences(doc, endorsement.ConfigPolicy{
			Identity: identity, Revision: revision, Digest: digest,
			Now: now, MaxAge: v.freshnessMaxAge,
		})
	})
	return verified, err
}

func (v *Verifier) configReferences(doc *document.Document, policy endorsement.ConfigPolicy) (*referenceValues, error) {
	config, err := doc.ConfigEndorsement()
	if err != nil {
		return nil, err
	}
	approved, err := v.configVerifier.Verify(config.Config, config.Bundle, policy)
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
	platformApprovedAt, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDPlatform, freshness.KindPlatform, &platform.AuthenticatedArtifact, policy.Now)
	if err != nil {
		return nil, fmt.Errorf("verifying platform freshness: %w", err)
	}
	runtimeApprovedAt, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDRuntime, freshness.KindRuntime, &authenticatedRuntime.AuthenticatedArtifact, policy.Now)
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
