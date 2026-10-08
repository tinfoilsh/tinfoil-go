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
}

// ConfigEndorsement is untrusted config material decoded from a document.
// Its reference must match the independently verified endorsement.
type ConfigEndorsement struct {
	Reference string
	Config    []byte
	Bundle    jsontext.Value
}

func decodeConfigEndorsement(entry *Entry) (ConfigEndorsement, error) {
	var c configCollateral
	if err := unmarshalData(entry, entry.Format, &c); err != nil {
		return ConfigEndorsement{}, err
	}
	digest, ok := strings.CutPrefix(c.Reference, "sha256:")
	if !ok {
		return ConfigEndorsement{}, fmt.Errorf("endorsement_ref must be a SHA-256 reference")
	}
	if _, err := canonical.DecodeLowerHex("endorsement_ref", digest, sha256.Size); err != nil {
		return ConfigEndorsement{}, err
	}
	config, err := canonical.DecodeBase64("config_base64", c.Config)
	if err != nil {
		return ConfigEndorsement{}, err
	}
	if len(config) == 0 {
		return ConfigEndorsement{}, fmt.Errorf("config_base64 must not be empty")
	}
	if c.Bundle.Kind() != '{' {
		return ConfigEndorsement{}, fmt.Errorf("sigstore_bundle must be an object")
	}
	return ConfigEndorsement{Reference: c.Reference, Config: config, Bundle: c.Bundle}, nil
}

func (c ConfigEndorsement) Clone() ConfigEndorsement {
	c.Config = slices.Clone(c.Config)
	c.Bundle = slices.Clone(c.Bundle)
	return c
}
