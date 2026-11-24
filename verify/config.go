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

// PublicRegistryID is Tinfoil's public config registry, which default config
// trust accepts. List it in Registries to keep accepting public configs
// alongside a private registry.
const PublicRegistryID = configendorsement.PublicRegistryID

// ConfigTrust selects who vouches for the config that an enclave runs. It is
// one of Registries, ConfigSigningKeys, ConfigAuthorizer, EmbeddedConfig or
// EmbeddedConfigReference, passed as a value; nil selects the public registry.
// Every choice other than nil requires attestation-collaterals/v3.
type ConfigTrust interface {
	configTrust()
}

// Registries trusts configs that exactly these registries endorse, under
// Tinfoil's registry root, in place of the public registry alone. To keep the
// public registry, list PublicRegistryID. IDs must not be empty.
type Registries struct {
	IDs []string
}

// ConfigSigningKeys trusts configs whose endorsements these keys sign, in
// place of Tinfoil's registry root. This explicit trust path does not use
// registry IDs or authorize artifact freshness. Keys must not be empty.
type ConfigSigningKeys struct {
	Keys []crypto.PublicKey
}

// ConfigAuthorizer replaces config endorsement verification with caller
// policy. Authorize receives detached, untrusted material and must reject
// unauthorized config bytes. It may be called concurrently. Runtime, platform
// and hardware checks still apply; approval does not authenticate a registry
// name or timestamp, so a Project pin is a UsageError.
//
// The runtime pin is read from the bytes that Authorize approves, which must
// be a JSON config. Verification rejects any other bytes, such as the YAML
// config that earlier enclave versions take.
type ConfigAuthorizer struct {
	Authorize func(collateral.ConfigEndorsement) error
}

func (Registries) configTrust()        {}
func (ConfigSigningKeys) configTrust() {}
func (ConfigAuthorizer) configTrust()  {}

// applyConfigTrust copies config into v after checking it. It runs after
// applyArtifactTrust, so that an embedded config can check an embedded runtime.
func (v *Verifier) applyConfigTrust(config ConfigTrust) error {
	switch c := config.(type) {
	case nil:
		return nil
	case Registries:
		if len(c.IDs) == 0 {
			return fmt.Errorf("config registry IDs must not be empty")
		}
		ids := slices.Clone(c.IDs)
		if err := (endorsement.ConfigPolicy{RegistryIDs: ids}).ValidatePins(); err != nil {
			return err
		}
		v.configRegistryIDs = ids
		return nil
	case ConfigSigningKeys:
		if len(c.Keys) == 0 {
			return fmt.Errorf("config signing keys must not be empty")
		}
		v.configKeys = slices.Clone(c.Keys)
		return nil
	case ConfigAuthorizer:
		if c.Authorize == nil {
			return fmt.Errorf("config authorizer must not be nil")
		}
		v.configAuthorizer = c.Authorize
		return nil
	case EmbeddedConfig:
		reference, err := c.reference()
		if err != nil {
			return err
		}
		return v.applyEmbeddedConfig(reference)
	case EmbeddedConfigReference:
		return v.applyEmbeddedConfig(c)
	default:
		return fmt.Errorf("config trust must be a Registries, ConfigSigningKeys, ConfigAuthorizer, EmbeddedConfig or EmbeddedConfigReference value, not %T", config)
	}
}

// referencePins returns the config pins ref sets under v's policy, or a usage
// error if VerifyV3 rejects ref whatever the document. Every check of that
// kind belongs here, so CheckPinVerifiability makes it too.
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
	if embedded := v.embedded.config; embedded != nil {
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
	if embedded := v.embedded.config; embedded != nil {
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
	if v.embedded.runtime != nil {
		manifest, err := runtime.ParseManifest(v.embedded.runtime, expected)
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
	if v.embedded.platform != nil {
		artifact, err := platformpolicy.Parse(v.embedded.platform)
		digest := sha256.Sum256(v.embedded.platform)
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
