package verify

import (
	"bytes"
	"fmt"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

// EmbeddedConfig authorizes exact config bytes without a registry endorsement.
// Name optionally associates them with a trusted /org/project/revision identity.
type EmbeddedConfig struct {
	Name  string
	Bytes []byte
}

// EmbeddedReferences replaces endorsement and renewal checks only for supplied
// components of attestation-collaterals/v3. Nil components retain normal checks.
// Runtime is the exact manifest pinned by the config; Platform is a platform
// policy artifact. Hardware authentication, component bindings, and pins remain
// mandatory. These values must come from trusted client configuration.
type EmbeddedReferences struct {
	Config   *EmbeddedConfig
	Runtime  []byte
	Platform []byte
}

// WithEmbeddedReferences copies caller-trusted values into an immutable policy.
// No endorsement is consulted for a supplied component, even if one is present.
func WithEmbeddedReferences(refs EmbeddedReferences) Option {
	return func(v *Verifier) error {
		if refs.Config == nil && refs.Runtime == nil && refs.Platform == nil {
			return fmt.Errorf("embedded references must contain at least one component")
		}
		copied := EmbeddedReferences{Runtime: bytes.Clone(refs.Runtime), Platform: bytes.Clone(refs.Platform)}
		if refs.Config != nil {
			if len(refs.Config.Bytes) == 0 || len(refs.Config.Bytes) > configendorsement.MaxConfigSize {
				return fmt.Errorf("embedded config size is outside allowed bounds")
			}
			if refs.Config.Name != "" {
				if _, _, err := configendorsement.ParseName(refs.Config.Name); err != nil {
					return err
				}
			}
			if _, err := runtime.ConfigRuntime(refs.Config.Bytes); err != nil {
				return err
			}
			copied.Config = &EmbeddedConfig{Name: refs.Config.Name, Bytes: bytes.Clone(refs.Config.Bytes)}
		}
		if refs.Runtime != nil && (len(refs.Runtime) == 0 || len(refs.Runtime) > runtime.MaxManifestSize) {
			return fmt.Errorf("embedded runtime manifest size is outside allowed bounds")
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
	return v.embedded.Config != nil || v.embedded.Runtime != nil || v.embedded.Platform != nil || v.configKeys != nil || v.freshnessKeys != nil
}
