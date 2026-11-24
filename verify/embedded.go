package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

// EmbeddedConfig trusts exact config bytes that the caller supplies, in place
// of a registry endorsement. Name optionally associates them with a trusted
// /org/project/revision identity, which a Project pin must then match. The
// config must come from trusted client configuration, and requires
// attestation-collaterals/v3.
//
// Bytes must be a JSON config, which the runtime pin is read from. NewVerifier
// refuses any other bytes, such as the YAML config of a cvm-version before
// configendorsement.JSONConfigMinVersion; EmbeddedConfigReference trusts such
// a config.
type EmbeddedConfig struct {
	Name  string
	Bytes []byte
}

// EmbeddedConfigReference trusts an exact config, identified by the hex
// SHA-256 Digest of its bytes, and the runtime that it pins, in place of a
// registry endorsement. Otherwise it is EmbeddedConfig.
type EmbeddedConfigReference struct {
	Name    string
	Digest  string
	Runtime configendorsement.RuntimeReference
}

func (EmbeddedConfig) configTrust()          {}
func (EmbeddedConfigReference) configTrust() {}

// embeddedReferences are the caller-trusted values that replace an
// endorsement: a nil member keeps the endorsement of that component.
type embeddedReferences struct {
	config   *EmbeddedConfigReference
	runtime  []byte
	platform []byte
}

// reference returns the config reference that c's bytes determine.
func (c EmbeddedConfig) reference() (EmbeddedConfigReference, error) {
	if len(c.Bytes) == 0 || len(c.Bytes) > configendorsement.MaxConfigSize {
		return EmbeddedConfigReference{}, fmt.Errorf("embedded config size is outside allowed bounds")
	}
	expected, err := configendorsement.RuntimeFromConfig(c.Bytes)
	if err != nil {
		return EmbeddedConfigReference{}, fmt.Errorf("embedded config bytes must be a JSON config; trust any other config with EmbeddedConfigReference: %w", err)
	}
	digest := sha256.Sum256(c.Bytes)
	return EmbeddedConfigReference{Name: c.Name, Digest: hex.EncodeToString(digest[:]), Runtime: expected}, nil
}

// applyEmbeddedConfig checks reference, and any embedded runtime against it,
// and stores it in v. It runs after applyArtifactTrust.
func (v *Verifier) applyEmbeddedConfig(reference EmbeddedConfigReference) error {
	if reference.Name != "" {
		if _, _, err := configendorsement.ParseName(reference.Name); err != nil {
			return err
		}
	}
	if _, err := canonical.DecodeLowerHex("config digest", reference.Digest, sha256.Size); err != nil {
		return err
	}
	if err := reference.Runtime.Validate(); err != nil {
		return err
	}
	// Both come from the caller, so a manifest that the config does not pin
	// is rejected here rather than at verification.
	if v.embedded.runtime != nil {
		if _, err := runtime.ParseManifest(v.embedded.runtime, reference.Runtime); err != nil {
			return err
		}
	}
	v.embedded.config = &reference
	return nil
}

func (v *Verifier) requiresConfigCollateral() bool {
	return v.embedded.config != nil || v.embedded.runtime != nil || v.embedded.platform != nil || v.configKeys != nil || v.freshnessKeys != nil || v.configAuthorizer != nil || v.configRegistryIDs != nil
}
