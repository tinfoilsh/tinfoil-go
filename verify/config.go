package verify

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"golang.org/x/mod/semver"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	platformpolicy "github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

// WithConfigRegistryIDs accepts exactly these registry IDs, replacing public-only trust.
func WithConfigRegistryIDs(registryIDs ...string) Option {
	registryIDs = slices.Clone(registryIDs)
	return func(v *Verifier) error {
		if len(registryIDs) == 0 {
			return fmt.Errorf("config registry IDs must not be empty")
		}
		if err := (endorsement.ConfigPolicy{RegistryIDs: registryIDs}).ValidatePins(); err != nil {
			return err
		}
		if v.configRegistryIDs != nil {
			return fmt.Errorf("config registry IDs must be supplied once")
		}
		v.configRegistryIDs = slices.Clone(registryIDs)
		return nil
	}
}

// WithAdditionalConfigRegistryIDs accepts these registry IDs alongside the public registry.
func WithAdditionalConfigRegistryIDs(registryIDs ...string) Option {
	registryIDs = slices.Clone(registryIDs)
	return func(v *Verifier) error {
		if len(registryIDs) == 0 {
			return fmt.Errorf("additional config registry IDs must not be empty")
		}
		return WithConfigRegistryIDs(append([]string{configendorsement.PublicRegistryID}, registryIDs...)...)(v)
	}
}

// WithConfigAuthorizer replaces config endorsement verification with caller policy.
// The callback receives detached, untrusted material and must reject unauthorized
// config bytes. It may be called concurrently. Runtime, platform, and hardware
// checks still apply; approval does not authenticate a registry name or timestamp.
func WithConfigAuthorizer(authorize func(collateral.ConfigEndorsement) error) Option {
	return func(v *Verifier) error {
		if authorize == nil {
			return fmt.Errorf("config authorizer must not be nil")
		}
		v.configAuthorizer = authorize
		return nil
	}
}

// WithConfigSigningKeys replaces public config trust with the supplied keys.
// This explicit trust path does not use registry IDs or authorize artifact freshness.
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

// referencePins returns the config pins ref sets under v's policy, or a usage
// error if VerifyV3 rejects ref whatever the document. Every check of that
// kind belongs here, so CheckRepoVerifiability makes it too.
func (v *Verifier) referencePins(ref string) (endorsement.ConfigPolicy, error) {
	pins := endorsement.ConfigPolicy{RegistryIDs: v.configRegistryIDs}
	if pins.RegistryIDs == nil && v.configKeys == nil {
		pins.RegistryIDs = []string{configendorsement.PublicRegistryID}
	}
	if v.configAuthorizer != nil && ref != "" {
		return pins, usageError(fmt.Errorf("config authorizer cannot authenticate repository or revision pins; enforce them in caller policy"))
	}
	if ref != "" {
		parsed, err := endorsement.ParseReference(ref)
		if err != nil {
			return pins, usageError(err)
		}
		pins.Identity, pins.Revision, pins.Digest = "/"+parsed.Repo, parsed.Tag, parsed.Digest
	}
	if embedded := v.embedded.ConfigReference; embedded != nil {
		var identity, revision string
		if embedded.Name != "" {
			var err error
			if identity, revision, err = configendorsement.ParseName(embedded.Name); err != nil {
				return pins, usageError(err)
			}
		}
		if (pins.Identity != "" && pins.Identity != identity) || (pins.Revision != "" && pins.Revision != revision) || (pins.Digest != "" && pins.Digest != embedded.Digest) {
			return pins, usageError(fmt.Errorf("embedded config does not match the caller's pins"))
		}
	}
	return pins, nil
}

func (v *Verifier) configReferences(doc *document.Document, ref string, now time.Time) (*endorsementResult, error) {
	pins, err := v.referencePins(ref)
	if err != nil {
		return nil, err
	}
	// Config identities and revisions are stricter than the repository
	// references v2 collateral accepts, so only v3 collateral checks them.
	if pins.Identity != "" {
		if err := pins.ValidatePins(); err != nil {
			return nil, usageError(err)
		}
	}
	pins.Now, pins.MaxAge = now, v.freshnessMaxAge
	expectedRuntime, approved, err := v.resolveConfig(doc, pins)
	if err != nil {
		return nil, err
	}
	digest, err := canonical.DecodeLowerHex("config digest", approved.Digest, sha256.Size)
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
			Hash:         [sha256.Size]byte(digest),
		},
		artifact: runtimeTrust,
		platform: &platformTrust,
		config:   approved,
	}
	result.freshnessExpiresAt = freshnessExpiration(v.freshnessMaxAge, approved.ApprovalTime, platformTrust.ApprovalTime, runtimeTrust.ApprovalTime)

	return result, nil
}

func (v *Verifier) resolveConfig(doc *document.Document, pins endorsement.ConfigPolicy) (collateral.RuntimeReference, *ConfigVerification, error) {
	var expected collateral.RuntimeReference
	if embedded := v.embedded.ConfigReference; embedded != nil {
		// referencePins matched the pins against it.
		return embedded.Runtime, &ConfigVerification{Source: SourceEmbedded, Name: embedded.Name, Digest: embedded.Digest}, nil
	}
	config, err := doc.ConfigEndorsement()
	if err != nil {
		return expected, nil, err
	}
	if v.configAuthorizer != nil {
		if len(config.Config) == 0 || len(config.Config) > configendorsement.MaxConfigSize {
			return expected, nil, fmt.Errorf("config size is outside allowed bounds")
		}
		if err := v.configAuthorizer(config.Clone()); err != nil {
			return expected, nil, &VerificationError{Layer: LayerProvenance, Err: fmt.Errorf("authorizing config: %w", err)}
		}
		digest := sha256.Sum256(config.Config)
		expected, err := configendorsement.RuntimeFromConfig(config.Config)
		return expected, &ConfigVerification{Source: SourcePolicy, Digest: hex.EncodeToString(digest[:])}, err
	}
	if len(config.Bundle) == 0 {
		return expected, nil, fmt.Errorf("unsigned config requires a config authorizer")
	}
	var approved *endorsement.ConfigVerified
	if config.Issuer != nil && v.configKeys == nil {
		approved, err = v.configVerifier.VerifyCertified(config.Config, config.Bundle, config.Issuer, pins)
	} else {
		approved, err = v.configVerifier.Verify(config.Config, config.Bundle, pins)
	}
	if err != nil {
		return expected, nil, fmt.Errorf("verifying config approval: %w", err)
	}
	if config.Reference != approved.Reference {
		return expected, nil, fmt.Errorf("config endorsement reference does not match the verified approval")
	}
	if approved.Runtime != nil {
		expected = *approved.Runtime
	} else {
		expected, err = configendorsement.RuntimeFromConfig(config.Config)
		if err != nil {
			return expected, nil, err
		}
	}
	return expected, &ConfigVerification{
		Source: SourceEndorsement, Name: approved.Name, Digest: approved.Digest,
		Reference: approved.Reference, SigningKeyHint: approved.SigningKeyHint, ApprovalTime: approved.ApprovalTime,
		RegistryID: approved.RegistryID, SignatureTime: approved.SignatureTime,
	}, nil
}

func (v *Verifier) resolveRuntime(doc *document.Document, expected collateral.RuntimeReference, now time.Time) (*runtime.Manifest, ArtifactVerification, error) {
	if v.embedded.Runtime != nil {
		manifest, err := runtime.ParseManifest(v.embedded.Runtime, expected)
		return manifest, ArtifactVerification{Source: SourceEmbedded, Repo: expected.Repo, Tag: semver.Canonical(expected.Tag), Digest: expected.Digest}, err
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
	platform, err := v.endorsements.AuthenticatePlatformEndorsements(material.Bundle, material.Repo, material.Tag, material.Digest, platformpolicy.ArtifactFormatV2)
	if err != nil {
		return nil, ArtifactVerification{}, err
	}
	if platform.SubjectName != freshness.PlatformName {
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
		Now:      now, MaxAge: v.freshnessMaxAge,
	})
	if err != nil {
		return time.Time{}, err
	}
	return approved.ApprovalTime, nil
}
