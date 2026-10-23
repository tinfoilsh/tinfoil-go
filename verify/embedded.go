package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

// EmbeddedConfig authorizes exact config bytes without a registry endorsement.
// Name optionally associates them with a trusted /org/project/revision identity.
type EmbeddedConfig struct {
	Name  string
	Bytes []byte
}

// EmbeddedConfigReference authorizes an exact config/runtime pair supplied by the caller.
type EmbeddedConfigReference struct {
	Name    string
	Digest  string
	Runtime configendorsement.RuntimeReference
}

// EmbeddedReferences replaces endorsement and renewal checks only for supplied
// components of attestation-collaterals/v3. Nil components retain normal checks.
// Runtime is the exact manifest pinned by the config; Platform is a platform
// policy artifact. Hardware authentication, component bindings, and pins remain
// mandatory. These values must come from trusted client configuration.
type EmbeddedReferences struct {
	Config          *EmbeddedConfig
	ConfigReference *EmbeddedConfigReference
	Runtime         []byte
	Platform        []byte
}

// WithEmbeddedReferences copies caller-trusted values into an immutable policy.
// No endorsement is consulted for a supplied component, even if one is present.
func WithEmbeddedReferences(refs EmbeddedReferences) Option {
	return func(v *Verifier) error {
		if refs.Config == nil && refs.ConfigReference == nil && refs.Runtime == nil && refs.Platform == nil {
			return fmt.Errorf("embedded references must contain at least one component")
		}
		if refs.Config != nil && refs.ConfigReference != nil {
			return fmt.Errorf("embedded config bytes and reference are mutually exclusive")
		}
		copied := EmbeddedReferences{Runtime: bytes.Clone(refs.Runtime), Platform: bytes.Clone(refs.Platform)}
		if refs.ConfigReference != nil {
			reference := *refs.ConfigReference
			copied.ConfigReference = &reference
		}
		if refs.Config != nil {
			if len(refs.Config.Bytes) == 0 || len(refs.Config.Bytes) > configendorsement.MaxConfigSize {
				return fmt.Errorf("embedded config size is outside allowed bounds")
			}
			expected, err := configendorsement.RuntimeFromConfig(refs.Config.Bytes)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(refs.Config.Bytes)
			copied.ConfigReference = &EmbeddedConfigReference{Name: refs.Config.Name, Digest: hex.EncodeToString(digest[:]), Runtime: expected}
		}
		if reference := copied.ConfigReference; reference != nil {
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
			// Both come from the caller, so a manifest the config does not
			// pin is rejected here rather than at verification.
			if refs.Runtime != nil {
				if _, err := runtime.ParseManifest(refs.Runtime, reference.Runtime); err != nil {
					return err
				}
			}
		}
		if refs.Runtime != nil {
			if _, err := runtime.DecodeManifest(refs.Runtime); err != nil {
				return err
			}
		}
		if refs.Platform != nil {
			artifact, err := policy.Parse(refs.Platform)
			if err != nil {
				return err
			}
			if artifact.Format != policy.ArtifactFormatV2 {
				return fmt.Errorf("embedded platform requires platform-endorsements/v2")
			}
		}
		v.embedded = copied
		return nil
	}
}

func (v *Verifier) requiresConfigCollateral() bool {
	return v.embedded.ConfigReference != nil || v.embedded.Runtime != nil || v.embedded.Platform != nil || v.configKeys != nil || v.freshnessKeys != nil || v.configAuthorizer != nil || v.configPins != (ConfigPins{})
}
