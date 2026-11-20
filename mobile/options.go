package mobile

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"time"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// PublicRegistryID is Tinfoil's public config registry. List it in a
// "registries" config trust to keep accepting public configs alongside a
// private registry.
const PublicRegistryID = verify.PublicRegistryID

// options is the JSON object that NewVerifier accepts. Both members are
// optional; an absent or null member keeps the default, and a present one must
// be valid. Byte strings are standard base64 with padding.
type options struct {
	// ConfigTrust is one of the tagged objects that configTrustType names,
	// decoded once its type is known. Absent, it selects the public registry.
	ConfigTrust jsontext.Value `json:"config_trust,omitempty"`
	// Policy is the verifier's policy. Absent, it selects the default policy.
	Policy *policyJSON `json:"policy,omitempty"`
}

// policyJSON is the policy object, which NewVerifierWithConfigAuthorizer
// takes on its own.
type policyJSON struct {
	PinnedRegisters   *measurementJSON `json:"pinned_registers,omitempty"`
	FreshnessMaxAgeNs int64            `json:"freshness_max_age_ns,omitempty"`
	// Artifacts is one of the tagged objects that artifactsType names,
	// decoded once its type is known. Absent, it selects endorsed artifacts
	// approved by Tinfoil's freshness keys.
	Artifacts jsontext.Value `json:"artifacts,omitempty"`
}

// The tagged config trust objects, by their "type".
type (
	registriesJSON struct {
		Type string `json:"type"`
		// IDs replaces public-only config trust with exactly these
		// registries. Include PublicRegistryID to keep the public registry.
		IDs []string `json:"ids"`
	}
	signingKeysJSON struct {
		Type string `json:"type"`
		// KeysPEM are PKIX public keys, each one PEM "PUBLIC KEY" block.
		KeysPEM []string `json:"keys_pem"`
	}
	embeddedConfigJSON struct {
		Type  string `json:"type"`
		Name  string `json:"name,omitempty"`
		Bytes string `json:"bytes"`
	}
	embeddedConfigReferenceJSON struct {
		Type    string               `json:"type"`
		Name    string               `json:"name,omitempty"`
		Digest  string               `json:"digest"`
		Runtime runtimeReferenceJSON `json:"runtime"`
	}
)

type runtimeReferenceJSON struct {
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

// The tagged artifact trust objects, by their "type".
type (
	endorsedArtifactsJSON struct {
		Type string `json:"type"`
		// FreshnessKeysPEM are PKIX public keys, each one PEM "PUBLIC KEY"
		// block. Absent, they select Tinfoil's public freshness keys.
		FreshnessKeysPEM []string `json:"freshness_keys_pem,omitempty"`
	}
	embeddedArtifactsJSON struct {
		Type             string   `json:"type"`
		Runtime          *string  `json:"runtime,omitempty"`
		Platform         *string  `json:"platform,omitempty"`
		FreshnessKeysPEM []string `json:"freshness_keys_pem,omitempty"`
	}
)

// strict rejects unknown members, including those that do not belong to the
// chosen type of a tagged object. Duplicate members are rejected by default.
var strict = json.RejectUnknownMembers(true)

// parseOptions decodes optionsJSON, where "" selects the defaults, into the
// verifier's config trust and policy. Any malformed or unknown member is a
// usage error.
func parseOptions(optionsJSON string) (verify.ConfigTrust, verify.Policy, error) {
	if optionsJSON == "" {
		return nil, verify.Policy{}, nil
	}
	var opts *options
	if err := json.Unmarshal([]byte(optionsJSON), &opts, strict); err != nil {
		return nil, verify.Policy{}, fmt.Errorf("parsing verification options: %w", err)
	}
	if opts == nil {
		return nil, verify.Policy{}, fmt.Errorf("verification options must be a JSON object")
	}
	config, err := configTrust(opts.ConfigTrust)
	if err != nil {
		return nil, verify.Policy{}, err
	}
	policy, err := opts.Policy.policy()
	if err != nil {
		return nil, verify.Policy{}, err
	}
	return config, policy, nil
}

// parsePolicy decodes encoded, the policy object alone, where "" selects the
// default policy. Any malformed or unknown member is a usage error.
func parsePolicy(encoded string) (verify.Policy, error) {
	if encoded == "" {
		return verify.Policy{}, nil
	}
	var p *policyJSON
	if err := json.Unmarshal([]byte(encoded), &p, strict); err != nil {
		return verify.Policy{}, fmt.Errorf("parsing verification policy: %w", err)
	}
	if p == nil {
		return verify.Policy{}, fmt.Errorf("verification policy must be a JSON object")
	}
	return p.policy()
}

// typeOf returns the "type" member of raw, a tagged object, and whether raw is
// present at all: an absent or null member is not. The other members are
// checked once the type is known.
func typeOf(member string, raw jsontext.Value) (string, bool, error) {
	if len(raw) == 0 || raw.Kind() == 'n' {
		return "", false, nil
	}
	var tag struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &tag); err != nil {
		return "", false, fmt.Errorf("parsing %s: %w", member, err)
	}
	if tag.Type == "" {
		return "", false, fmt.Errorf("%s requires a type", member)
	}
	return tag.Type, true, nil
}

// decodeTagged decodes raw into v, the struct for its type, rejecting any
// member that does not belong to that type.
func decodeTagged(member, tag string, raw jsontext.Value, v any) error {
	if err := json.Unmarshal(raw, v, strict); err != nil {
		return fmt.Errorf("parsing %s of type %q: %w", member, tag, err)
	}
	return nil
}

// configTrust translates raw, the config_trust member, into the verifier's
// config trust. The verifier checks each value.
func configTrust(raw jsontext.Value) (verify.ConfigTrust, error) {
	const member = "config_trust"
	tag, present, err := typeOf(member, raw)
	if err != nil || !present {
		return nil, err
	}
	switch tag {
	case "registries":
		var c registriesJSON
		if err := decodeTagged(member, tag, raw, &c); err != nil {
			return nil, err
		}
		// A missing or empty list reaches the verifier, which rejects it.
		return verify.Registries{IDs: c.IDs}, nil
	case "signing_keys":
		var c signingKeysJSON
		if err := decodeTagged(member, tag, raw, &c); err != nil {
			return nil, err
		}
		keys, err := parsePublicKeys("config signing key", c.KeysPEM)
		if err != nil {
			return nil, err
		}
		return verify.ConfigSigningKeys{Keys: keys}, nil
	case "embedded_config":
		var c embeddedConfigJSON
		if err := decodeTagged(member, tag, raw, &c); err != nil {
			return nil, err
		}
		config, err := decodeBase64("config_trust.bytes", c.Bytes)
		if err != nil {
			return nil, err
		}
		return verify.EmbeddedConfig{Name: c.Name, Bytes: config}, nil
	case "embedded_config_reference":
		var c embeddedConfigReferenceJSON
		if err := decodeTagged(member, tag, raw, &c); err != nil {
			return nil, err
		}
		return verify.EmbeddedConfigReference{
			Name:    c.Name,
			Digest:  c.Digest,
			Runtime: configendorsement.RuntimeReference{Repo: c.Runtime.Repo, Tag: c.Runtime.Tag, Digest: c.Runtime.Digest},
		}, nil
	default:
		return nil, fmt.Errorf("%s has unknown type %q", member, tag)
	}
}

// policy translates p into the verifier's policy. A nil receiver is the
// default policy.
func (p *policyJSON) policy() (verify.Policy, error) {
	if p == nil {
		return verify.Policy{}, nil
	}
	pins, err := p.PinnedRegisters.expected()
	if err != nil {
		return verify.Policy{}, err
	}
	artifacts, err := artifactTrust(p.Artifacts)
	if err != nil {
		return verify.Policy{}, err
	}
	return verify.Policy{PinnedRegisters: pins, FreshnessMaxAge: time.Duration(p.FreshnessMaxAgeNs), Artifacts: artifacts}, nil
}

// artifactTrust translates raw, the policy's artifacts member, into the
// verifier's artifact trust. The verifier checks each value.
func artifactTrust(raw jsontext.Value) (verify.ArtifactTrust, error) {
	const member = "artifacts"
	tag, present, err := typeOf(member, raw)
	if err != nil || !present {
		return nil, err
	}
	switch tag {
	case "endorsed":
		var a endorsedArtifactsJSON
		if err := decodeTagged(member, tag, raw, &a); err != nil {
			return nil, err
		}
		keys, err := freshnessKeys(a.FreshnessKeysPEM)
		if err != nil {
			return nil, err
		}
		return verify.EndorsedArtifacts{FreshnessKeys: keys}, nil
	case "embedded":
		var a embeddedArtifactsJSON
		if err := decodeTagged(member, tag, raw, &a); err != nil {
			return nil, err
		}
		keys, err := freshnessKeys(a.FreshnessKeysPEM)
		if err != nil {
			return nil, err
		}
		embedded := verify.EmbeddedArtifacts{FreshnessKeys: keys}
		if a.Runtime != nil {
			if embedded.Runtime, err = decodeBase64("artifacts.runtime", *a.Runtime); err != nil {
				return nil, err
			}
		}
		if a.Platform != nil {
			if embedded.Platform, err = decodeBase64("artifacts.platform", *a.Platform); err != nil {
				return nil, err
			}
		}
		return embedded, nil
	default:
		return nil, fmt.Errorf("%s has unknown type %q", member, tag)
	}
}

// freshnessKeys parses pemKeys, keeping nil, which selects Tinfoil's public
// keys, apart from an empty list, which the verifier rejects.
func freshnessKeys(pemKeys []string) ([]crypto.PublicKey, error) {
	if pemKeys == nil {
		return nil, nil
	}
	return parsePublicKeys("freshness signing key", pemKeys)
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
