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
	Reference string                      `json:"endorsement_ref"`
	Config    string                      `json:"config_base64"`
	Bundle    jsontext.Value              `json:"sigstore_bundle"`
	Scope     *scopeCertificateCollateral `json:"scope,omitempty"`
}

type scopeCertificateCollateral struct {
	Certificate string         `json:"certificate_der"`
	Issuer      string         `json:"issuer_der"`
	Bundle      jsontext.Value `json:"issuance_bundle"`
}

type ScopeCertificate struct {
	Certificate []byte         `json:"certificate_der"`
	Issuer      []byte         `json:"issuer_der"`
	Bundle      jsontext.Value `json:"issuance_bundle"`
}

// ConfigEndorsement is untrusted config material decoded from a document.
// Plain config collateral has no Reference or Bundle and requires caller authorization.
// A signed reference must match the independently verified endorsement.
type ConfigEndorsement struct {
	Reference string
	Config    []byte
	Bundle    jsontext.Value
	Scope     *ScopeCertificate
}

func decodeConfigEndorsement(entry *Entry) (ConfigEndorsement, error) {
	var c configCollateral
	if err := unmarshalData(entry, entry.Format, &c); err != nil {
		return ConfigEndorsement{}, err
	}
	if c.Scope != nil && entry.Format != ConfigEndorsementV2Format {
		return ConfigEndorsement{}, fmt.Errorf("scope certificates require v2 config collateral")
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
	if c.Scope != nil {
		certificate, err := canonical.DecodeBase64("certificate_der", c.Scope.Certificate)
		if err != nil {
			return ConfigEndorsement{}, err
		}
		issuer, err := canonical.DecodeBase64("issuer_der", c.Scope.Issuer)
		if err != nil {
			return ConfigEndorsement{}, err
		}
		result.Scope = &ScopeCertificate{Certificate: certificate, Issuer: issuer, Bundle: c.Scope.Bundle}
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
	if c.Scope != nil {
		c.Scope = &ScopeCertificate{Certificate: slices.Clone(c.Scope.Certificate), Issuer: slices.Clone(c.Scope.Issuer), Bundle: slices.Clone(c.Scope.Bundle)}
	}
	return c
}
