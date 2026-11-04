package collateral

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

type configCollateral struct {
	Reference string         `json:"endorsement_ref"`
	Config    string         `json:"config_base64"`
	Bundle    jsontext.Value `json:"sigstore_bundle"`
	Issuer    string         `json:"issuer_certificate_der,omitempty"`
}

// ConfigEndorsement is untrusted config material decoded from a document.
// Plain config collateral has no Reference or Bundle and requires caller authorization.
// A signed reference must match the independently verified endorsement.
type ConfigEndorsement struct {
	Reference string
	Config    []byte
	Bundle    jsontext.Value
	Issuer    []byte
}

func decodeConfigEndorsement(entry *Entry) (ConfigEndorsement, error) {
	var c configCollateral
	if err := unmarshalData(entry, entry.Format, &c); err != nil {
		return ConfigEndorsement{}, err
	}
	if c.Issuer != "" && entry.Format != ConfigEndorsementV2Format {
		return ConfigEndorsement{}, fmt.Errorf("issuer certificates require v2 config collateral")
	}
	if entry.Format == ConfigV1Format {
		if c.Reference != "" || len(c.Bundle) != 0 {
			return ConfigEndorsement{}, fmt.Errorf("plain config collateral cannot contain an endorsement")
		}
	} else {
		digest, ok := strings.CutPrefix(c.Reference, "sha256:")
		if !ok {
			return ConfigEndorsement{}, fmt.Errorf("endorsement_ref must be a SHA-256 reference")
		}
		if _, err := canonical.DecodeLowerHex("endorsement_ref", digest, sha256.Size); err != nil {
			return ConfigEndorsement{}, err
		}
		if c.Bundle.Kind() != '{' {
			return ConfigEndorsement{}, fmt.Errorf("sigstore_bundle must be an object")
		}
	}
	result := ConfigEndorsement{Reference: c.Reference, Bundle: c.Bundle}
	if c.Issuer != "" {
		issuer, err := canonical.DecodeBase64("issuer_certificate_der", c.Issuer)
		if err != nil {
			return ConfigEndorsement{}, err
		}
		result.Issuer = issuer
	}
	if entry.Format == ConfigEndorsementV2Format && c.Config == "" {
		return result, nil
	}
	config, err := canonical.DecodeBase64("config_base64", c.Config)
	if err != nil {
		return ConfigEndorsement{}, err
	}
	if len(config) == 0 {
		return ConfigEndorsement{}, fmt.Errorf("config_base64 must not be empty")
	}
	result.Config = config
	return result, nil
}

func (c ConfigEndorsement) Clone() ConfigEndorsement {
	c.Config = slices.Clone(c.Config)
	c.Bundle = slices.Clone(c.Bundle)
	c.Issuer = slices.Clone(c.Issuer)
	return c
}
