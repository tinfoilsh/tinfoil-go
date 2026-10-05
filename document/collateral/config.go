package collateral

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

// ConfigEndorsement is a decoded ConfigEndorsementV1Format entry: the exact
// config bytes a registry approved, and the approval bundle. Both travel
// because SHA-256 of the bytes is the value the launch bound into its
// register. Nothing here is trusted until the bundle is verified against them.
type ConfigEndorsement struct {
	Config []byte
	Bundle jsontext.Value
}

// Clone returns a deep copy of c.
func (c ConfigEndorsement) Clone() ConfigEndorsement {
	return ConfigEndorsement{Config: slices.Clone(c.Config), Bundle: slices.Clone(c.Bundle)}
}

// configData is the data of a ConfigEndorsementV1Format entry. It names no
// digest and no revision; both are in the signed approval.
type configData struct {
	ConfigBase64   string         `json:"config_base64"`
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
}

func decodeConfigEndorsement(entry *Entry) (*ConfigEndorsement, error) {
	var data configData
	if err := unmarshalData(entry, entry.Format, &data); err != nil {
		return nil, err
	}
	config, err := canonical.DecodeBase64("config_base64", data.ConfigBase64)
	if err != nil {
		return nil, fmt.Errorf("%s collateral entry %q: %w", entry.Format, entry.ID, err)
	}
	if len(config) == 0 {
		return nil, fmt.Errorf("%s collateral entry %q carries no config", entry.Format, entry.ID)
	}
	if err := requireBundle(entry, data.SigstoreBundle); err != nil {
		return nil, err
	}
	return &ConfigEndorsement{Config: config, Bundle: data.SigstoreBundle}, nil
}
