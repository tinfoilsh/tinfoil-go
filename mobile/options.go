package mobile

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"time"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// PublicRegistryID is Tinfoil's public config registry. List it in
// config_registry_ids to keep accepting public configs alongside a private
// registry.
const PublicRegistryID = verify.PublicRegistryID

// options is the policy NewVerifier accepts as JSON. Every member is optional;
// an absent or null member keeps the default, and a present one must be valid.
// Byte strings are standard base64 with padding.
type options struct {
	PinnedRegisters   *measurementJSON `json:"pinned_registers,omitempty"`
	FreshnessMaxAgeNs int64            `json:"freshness_max_age_ns,omitempty"`

	// ConfigRegistryIDs replaces public-only config trust with exactly these
	// registries. Include PublicRegistryID to keep the public registry.
	ConfigRegistryIDs []string `json:"config_registry_ids,omitempty"`
	// ConfigSigningKeysPEM and FreshnessSigningKeysPEM are PKIX public keys,
	// each one PEM "PUBLIC KEY" block.
	ConfigSigningKeysPEM    []string `json:"config_signing_keys_pem,omitempty"`
	FreshnessSigningKeysPEM []string `json:"freshness_signing_keys_pem,omitempty"`

	// EmbeddedConfig, EmbeddedRuntime and EmbeddedPlatform are caller-trusted
	// references that replace the endorsement of that component.
	EmbeddedConfig   *embeddedConfigJSON `json:"embedded_config,omitempty"`
	EmbeddedRuntime  *string             `json:"embedded_runtime,omitempty"`
	EmbeddedPlatform *string             `json:"embedded_platform,omitempty"`
}

// embeddedConfigJSON is either exact config bytes, or the digest of a config
// and the runtime it pins. Name optionally gives either an /org/project/revision
// identity.
type embeddedConfigJSON struct {
	Name    string                `json:"name,omitempty"`
	Bytes   *string               `json:"bytes,omitempty"`
	Digest  string                `json:"digest,omitempty"`
	Runtime *runtimeReferenceJSON `json:"runtime,omitempty"`
}

type runtimeReferenceJSON struct {
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

// parseOptions decodes optionsJSON, where "" selects the defaults. Any
// malformed or unknown member is a usage error.
func parseOptions(optionsJSON string) (*options, error) {
	opts := &options{}
	if optionsJSON != "" {
		opts = nil
		if err := json.Unmarshal([]byte(optionsJSON), &opts, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("parsing verification options: %w", err)
		}
		if opts == nil {
			return nil, fmt.Errorf("verification options must be a JSON object")
		}
	}
	return opts, nil
}

// verifierInputs translates o, and authorize when it is not nil, into the
// verifier's config trust and policy. At most one member may select config
// trust; the verifier checks each value.
func (o *options) verifierInputs(authorize func(collateral.ConfigEndorsement) error) (verify.ConfigTrust, verify.Policy, error) {
	var config verify.ConfigTrust
	var source string
	selectConfig := func(name string, trust verify.ConfigTrust) error {
		if config != nil {
			return fmt.Errorf("%s and %s select conflicting config trust", source, name)
		}
		config, source = trust, name
		return nil
	}
	// A present but empty list reaches the verifier, which rejects it.
	if o.ConfigRegistryIDs != nil {
		if err := selectConfig("config_registry_ids", verify.Registries{IDs: o.ConfigRegistryIDs}); err != nil {
			return nil, verify.Policy{}, err
		}
	}
	if o.ConfigSigningKeysPEM != nil {
		keys, err := parsePublicKeys("config signing key", o.ConfigSigningKeysPEM)
		if err != nil {
			return nil, verify.Policy{}, err
		}
		if err := selectConfig("config_signing_keys_pem", verify.ConfigSigningKeys{Keys: keys}); err != nil {
			return nil, verify.Policy{}, err
		}
	}
	if o.EmbeddedConfig != nil {
		embedded, err := o.EmbeddedConfig.configTrust()
		if err != nil {
			return nil, verify.Policy{}, err
		}
		if err := selectConfig("embedded_config", embedded); err != nil {
			return nil, verify.Policy{}, err
		}
	}
	if authorize != nil {
		if err := selectConfig("config authorizer", verify.ConfigAuthorizer{Authorize: authorize}); err != nil {
			return nil, verify.Policy{}, err
		}
	}

	pins, err := o.PinnedRegisters.expected()
	if err != nil {
		return nil, verify.Policy{}, err
	}
	policy := verify.Policy{PinnedRegisters: pins, FreshnessMaxAge: time.Duration(o.FreshnessMaxAgeNs)}
	var freshnessKeys []crypto.PublicKey
	if o.FreshnessSigningKeysPEM != nil {
		if freshnessKeys, err = parsePublicKeys("freshness signing key", o.FreshnessSigningKeysPEM); err != nil {
			return nil, verify.Policy{}, err
		}
	}
	if o.EmbeddedRuntime != nil || o.EmbeddedPlatform != nil {
		embedded := verify.EmbeddedArtifacts{FreshnessKeys: freshnessKeys}
		if o.EmbeddedRuntime != nil {
			if embedded.Runtime, err = decodeBase64("embedded_runtime", *o.EmbeddedRuntime); err != nil {
				return nil, verify.Policy{}, err
			}
		}
		if o.EmbeddedPlatform != nil {
			if embedded.Platform, err = decodeBase64("embedded_platform", *o.EmbeddedPlatform); err != nil {
				return nil, verify.Policy{}, err
			}
		}
		policy.Artifacts = embedded
	} else if freshnessKeys != nil {
		policy.Artifacts = verify.EndorsedArtifacts{FreshnessKeys: freshnessKeys}
	}
	return config, policy, nil
}

// configTrust returns the embedded config that c describes.
func (c *embeddedConfigJSON) configTrust() (verify.ConfigTrust, error) {
	switch {
	case c.Bytes != nil && c.Digest == "" && c.Runtime == nil:
		config, err := decodeBase64("embedded_config.bytes", *c.Bytes)
		if err != nil {
			return nil, err
		}
		return verify.EmbeddedConfig{Name: c.Name, Bytes: config}, nil
	case c.Bytes == nil && c.Digest != "" && c.Runtime != nil:
		return verify.EmbeddedConfigReference{
			Name:    c.Name,
			Digest:  c.Digest,
			Runtime: configendorsement.RuntimeReference{Repo: c.Runtime.Repo, Tag: c.Runtime.Tag, Digest: c.Runtime.Digest},
		}, nil
	default:
		return nil, fmt.Errorf("embedded_config requires either bytes, or digest and runtime")
	}
}

// decodeBase64 accepts only the canonical standard encoding. Embedded
// components must not be empty, so "" is refused here rather than read as
// absent.
func decodeBase64(name, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s must not be empty", name)
	}
	return canonical.DecodeBase64(name, value)
}

// parsePublicKeys parses each entry as exactly one PEM "PUBLIC KEY" block
// holding a PKIX key, with nothing but whitespace around it.
func parsePublicKeys(name string, pemKeys []string) ([]crypto.PublicKey, error) {
	keys := make([]crypto.PublicKey, 0, len(pemKeys))
	for i, encoded := range pemKeys {
		// pem.Decode skips any text before the block, so check the start.
		trimmed := bytes.TrimSpace([]byte(encoded))
		block, rest := pem.Decode(trimmed)
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) || block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
			return nil, fmt.Errorf("%s %d must be a PEM PUBLIC KEY block", name, i)
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("%s %d must be a single PEM block", name, i)
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s %d: %w", name, i, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}
