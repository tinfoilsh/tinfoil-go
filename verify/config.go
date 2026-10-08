package verify

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	platformpolicy "github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

// WithConfigSigningKeys replaces public config trust with the supplied keys.
// These keys define the accepted audit scope and do not authorize artifact freshness.
// An explicit key set requires attestation-collaterals/v3.
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
// These keys do not authorize configs for any org. An explicit key set requires
// attestation-collaterals/v3 and at least one artifact using endorsed references.
func WithFreshnessSigningKeys(keys []crypto.PublicKey) Option {
	return func(v *Verifier) error {
		if len(keys) == 0 {
			return fmt.Errorf("freshness signing keys must not be empty")
		}
		v.freshnessKeys = append([]crypto.PublicKey(nil), keys...)
		return nil
	}
}

func (v *Verifier) configReferences(doc *document.Document, ref string, now time.Time) (*endorsementResult, error) {
	pins := endorsement.ConfigPolicy{Now: now, MaxAge: v.freshnessMaxAge, IgnoreFreshness: v.ignoreFreshness}
	if ref != "" || v.embedded.Config == nil {
		name, revision, digest, err := endorsement.ParseReference(ref)
		if err != nil {
			return nil, configurationError(err)
		}
		pins.Identity, pins.Revision, pins.Digest = "/"+name, revision, digest
		if err := pins.ValidatePins(); err != nil {
			return nil, configurationError(err)
		}
	}
	config, approved, err := v.resolveConfig(doc, pins)
	if err != nil {
		return nil, err
	}
	expectedRuntime, err := runtime.ConfigRuntime(config)
	if err != nil {
		return nil, err
	}
	manifest, runtimeTrust, err := v.resolveRuntime(doc, expectedRuntime, now)
	if err != nil {
		return nil, err
	}
	platform, platformTrust, err := v.resolvePlatform(doc, now)
	if err != nil {
		return nil, err
	}
	result := &endorsementResult{
		quote: quote.ConfigReferenceValues{
			Endorsements: platform,
			Runtime:      manifest.Measurements,
			Hash:         sha256.Sum256(config),
		},
		artifact: runtimeTrust,
		platform: &platformTrust,
		config:   approved,
	}
	if !v.ignoreFreshness {
		result.freshnessExpiresAt = freshnessExpiration(v.freshnessMaxAge, approved.ApprovalTime, platformTrust.ApprovalTime, runtimeTrust.ApprovalTime)
	}
	return result, nil
}

func (v *Verifier) resolveConfig(doc *document.Document, pins endorsement.ConfigPolicy) ([]byte, *ConfigVerification, error) {
	if embedded := v.embedded.Config; embedded != nil {
		var identity, revision string
		if embedded.Name != "" {
			var err error
			identity, revision, err = configendorsement.ParseName(embedded.Name)
			if err != nil {
				return nil, nil, err
			}
		}
		digest := sha256.Sum256(embedded.Bytes)
		hexDigest := hex.EncodeToString(digest[:])
		if (pins.Identity != "" && pins.Identity != identity) || (pins.Revision != "" && pins.Revision != revision) || (pins.Digest != "" && pins.Digest != hexDigest) {
			return nil, nil, fmt.Errorf("embedded config does not match the caller's pins")
		}
		return embedded.Bytes, &ConfigVerification{Source: SourceEmbedded, Name: embedded.Name, Digest: hexDigest}, nil
	}
	config, err := doc.ConfigEndorsement()
	if err != nil {
		return nil, nil, err
	}
	approved, err := v.configVerifier.Verify(config.Config, config.Bundle, pins)
	if err != nil {
		return nil, nil, fmt.Errorf("verifying config approval: %w", err)
	}
	if config.Reference != approved.Reference {
		return nil, nil, fmt.Errorf("config endorsement reference does not match the verified approval")
	}
	return config.Config, &ConfigVerification{
		Source: SourceEndorsement, Name: approved.Name, Digest: approved.Digest,
		Reference: approved.Reference, SigningKeyHint: approved.SigningKeyHint, ApprovalTime: approved.ApprovalTime,
	}, nil
}

func (v *Verifier) resolveRuntime(doc *document.Document, expected collateral.RuntimeReference, now time.Time) (*runtime.Manifest, ArtifactVerification, error) {
	if v.embedded.Runtime != nil {
		manifest, err := runtime.ParseManifest(v.embedded.Runtime, expected)
		return manifest, ArtifactVerification{Source: SourceEmbedded, Repo: expected.Repo, Tag: expected.Tag, Digest: expected.Digest}, err
	}
	material, err := doc.Runtime()
	if err != nil {
		return nil, ArtifactVerification{}, err
	}
	authenticated, err := v.endorsements.AuthenticateRuntime(material, expected)
	if err != nil {
		return nil, ArtifactVerification{}, err
	}
	approvedAt, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDRuntime, freshness.KindRuntime, &authenticated.AuthenticatedArtifact, now)
	if err != nil {
		return nil, ArtifactVerification{}, fmt.Errorf("verifying runtime freshness: %w", err)
	}
	return authenticated.Manifest, artifactVerification(authenticated.AuthenticatedArtifact, approvedAt), nil
}

func (v *Verifier) resolvePlatform(doc *document.Document, now time.Time) (*platformpolicy.Artifact, ArtifactVerification, error) {
	if v.embedded.Platform != nil {
		artifact, err := platformpolicy.Parse(v.embedded.Platform)
		digest := sha256.Sum256(v.embedded.Platform)
		return artifact, ArtifactVerification{Source: SourceEmbedded, Digest: hex.EncodeToString(digest[:])}, err
	}
	material, err := doc.ConfigPlatform()
	if err != nil {
		return nil, ArtifactVerification{}, err
	}
	platform, err := v.endorsements.AuthenticatePlatformEndorsements(material.Bundle, material.Repo, material.Tag, material.Digest)
	if err != nil {
		return nil, ArtifactVerification{}, err
	}
	if platform.SubjectName != runtime.PlatformSubject {
		return nil, ArtifactVerification{}, fmt.Errorf("config verification requires its dedicated platform endorsement artifact")
	}
	approvedAt, err := v.authenticateArtifactFreshness(doc, collateral.FreshnessIDPlatform, freshness.KindPlatform, &platform.AuthenticatedArtifact, now)
	if err != nil {
		return nil, ArtifactVerification{}, fmt.Errorf("verifying platform freshness: %w", err)
	}
	return platform.Artifact, artifactVerification(platform.AuthenticatedArtifact, approvedAt), nil
}

func artifactVerification(artifact endorsement.AuthenticatedArtifact, approvedAt time.Time) ArtifactVerification {
	return ArtifactVerification{
		Source: SourceEndorsement, Repo: artifact.Repo, Tag: artifact.Tag, Digest: artifact.Digest,
		Name: artifact.SubjectName, Commit: artifact.Commit, ApprovalTime: approvedAt,
	}
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
		Now:      now, MaxAge: v.freshnessMaxAge, IgnoreFreshness: v.ignoreFreshness,
	})
	if err != nil {
		return time.Time{}, err
	}
	return approved.ApprovalTime, nil
}
