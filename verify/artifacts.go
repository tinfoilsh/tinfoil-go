package verify

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

// ArtifactTrust selects how a Verifier trusts the runtime and platform
// artifacts that attestation-collaterals/v3 references. It is one of
// EndorsedArtifacts or EmbeddedArtifacts, passed as a value; nil selects
// EndorsedArtifacts{}.
type ArtifactTrust interface {
	artifactTrust()
}

// EndorsedArtifacts trusts runtime and platform artifacts that the document's
// endorsements authenticate and whose freshness approvals FreshnessKeys sign.
//
// Nil FreshnessKeys selects Tinfoil's public keys. These keys approve platform
// and runtime artifacts only; they do not authorize configs for any org. An
// explicit key set requires attestation-collaterals/v3, and an empty one is
// invalid.
type EndorsedArtifacts struct {
	FreshnessKeys []crypto.PublicKey
}

// EmbeddedArtifacts trusts caller-supplied runtime and platform artifacts in
// place of their endorsements, and requires attestation-collaterals/v3.
//
// Runtime is the exact runtime manifest that the config pins, and Platform is
// a platform-endorsements/v2 policy artifact. No endorsement is consulted for
// a supplied artifact, even if the document carries one. A nil artifact is
// still endorsed, with its freshness approval signed by FreshnessKeys, which
// EndorsedArtifacts describes. At least one artifact must be supplied, and
// FreshnessKeys must be nil when both are, since nothing is left for them to
// verify. Hardware authentication, component bindings and pins remain
// mandatory. These values must come from trusted client configuration.
type EmbeddedArtifacts struct {
	Runtime       []byte
	Platform      []byte
	FreshnessKeys []crypto.PublicKey
}

func (EndorsedArtifacts) artifactTrust() {}
func (EmbeddedArtifacts) artifactTrust() {}

// applyArtifactTrust copies artifacts into v after checking it.
func (v *Verifier) applyArtifactTrust(artifacts ArtifactTrust) error {
	switch a := artifacts.(type) {
	case nil:
		return nil
	case EndorsedArtifacts:
		keys, err := freshnessKeys(a.FreshnessKeys)
		v.freshnessKeys = keys
		return err
	case EmbeddedArtifacts:
		if a.Runtime == nil && a.Platform == nil {
			return fmt.Errorf("embedded artifacts must contain a runtime or a platform")
		}
		if a.Runtime != nil && a.Platform != nil && a.FreshnessKeys != nil {
			return fmt.Errorf("freshness signing keys have no endorsed artifact to verify")
		}
		keys, err := freshnessKeys(a.FreshnessKeys)
		if err != nil {
			return err
		}
		if a.Runtime != nil {
			if _, err := runtime.DecodeManifest(a.Runtime); err != nil {
				return err
			}
		}
		if a.Platform != nil {
			artifact, err := policy.Parse(a.Platform)
			if err != nil {
				return err
			}
			if artifact.Format != policy.ArtifactFormatV2 {
				return fmt.Errorf("embedded platform requires platform-endorsements/v2")
			}
		}
		v.freshnessKeys = keys
		v.embedded.runtime = bytes.Clone(a.Runtime)
		v.embedded.platform = bytes.Clone(a.Platform)
		return nil
	default:
		return fmt.Errorf("artifact trust must be an EndorsedArtifacts or EmbeddedArtifacts value, not %T", artifacts)
	}
}

// freshnessKeys copies an explicit freshness key set. Nil selects Tinfoil's
// public keys and stays nil.
func freshnessKeys(keys []crypto.PublicKey) ([]crypto.PublicKey, error) {
	if keys == nil {
		return nil, nil
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("freshness signing keys must not be empty")
	}
	return slices.Clone(keys), nil
}
