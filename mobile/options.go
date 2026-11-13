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
)

// PublicRegistryID is Tinfoil's public config registry. List it in
// config_registry_ids to keep accepting public configs alongside a private
// registry.
const PublicRegistryID = configendorsement.PublicRegistryID

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

// parseOptions decodes optionsJSON, where "" selects the defaults, into
// verifier options. Any malformed or unknown member is a usage error.
func parseOptions(optionsJSON string) ([]verify.Option, error) {
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
	pins, err := opts.PinnedRegisters.expected()
	if err != nil {
		return nil, err
	}
	out := []verify.Option{
		verify.WithPinnedRegisters(pins),
		verify.WithFreshnessMaxAge(time.Duration(opts.FreshnessMaxAgeNs)),
	}
	// A present but empty list reaches the option, which rejects it.
	if opts.ConfigRegistryIDs != nil {
		out = append(out, verify.WithConfigRegistryIDs(opts.ConfigRegistryIDs...))
	}
	if opts.ConfigSigningKeysPEM != nil {
		keys, err := parsePublicKeys("config signing key", opts.ConfigSigningKeysPEM)
		if err != nil {
			return nil, err
		}
		out = append(out, verify.WithConfigSigningKeys(keys))
	}
	if opts.FreshnessSigningKeysPEM != nil {
		keys, err := parsePublicKeys("freshness signing key", opts.FreshnessSigningKeysPEM)
		if err != nil {
			return nil, err
		}
		out = append(out, verify.WithFreshnessSigningKeys(keys))
	}
	refs, err := opts.embeddedReferences()
	if err != nil {
		return nil, err
	}
	if refs != nil {
		out = append(out, verify.WithEmbeddedReferences(*refs))
	}
	return out, nil
}

// embeddedReferences returns nil when no component is embedded.
func (o *options) embeddedReferences() (*verify.EmbeddedReferences, error) {
	if o.EmbeddedConfig == nil && o.EmbeddedRuntime == nil && o.EmbeddedPlatform == nil {
		return nil, nil
	}
	var refs verify.EmbeddedReferences
	var err error
	if o.EmbeddedRuntime != nil {
		if refs.Runtime, err = decodeBase64("embedded_runtime", *o.EmbeddedRuntime); err != nil {
			return nil, err
		}
	}
	if o.EmbeddedPlatform != nil {
		if refs.Platform, err = decodeBase64("embedded_platform", *o.EmbeddedPlatform); err != nil {
			return nil, err
		}
	}
	if c := o.EmbeddedConfig; c != nil {
		switch {
		case c.Bytes != nil && c.Digest == "" && c.Runtime == nil:
			config, err := decodeBase64("embedded_config.bytes", *c.Bytes)
			if err != nil {
				return nil, err
			}
			refs.Config = &verify.EmbeddedConfig{Name: c.Name, Bytes: config}
		case c.Bytes == nil && c.Digest != "" && c.Runtime != nil:
			refs.ConfigReference = &verify.EmbeddedConfigReference{
				Name:    c.Name,
				Digest:  c.Digest,
				Runtime: configendorsement.RuntimeReference{Repo: c.Runtime.Repo, Tag: c.Runtime.Tag, Digest: c.Runtime.Digest},
			}
		default:
			return nil, fmt.Errorf("embedded_config requires either bytes, or digest and runtime")
		}
	}
	return &refs, nil
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
