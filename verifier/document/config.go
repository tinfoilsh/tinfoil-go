package document

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	"fmt"
	"strings"
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

func (d *Document) ConfigEndorsement() (ConfigEndorsement, error) {
	entry, err := d.uniqueReferenceValues(ConfigCollateralID, CollateralConfigEndorsementV1Format)
	if err != nil {
		return ConfigEndorsement{}, err
	}
	c, err := decodeCollateral[configCollateral](entry)
	if err != nil {
		return ConfigEndorsement{}, err
	}
	digest, ok := strings.CutPrefix(c.Reference, "sha256:")
	if !ok {
		return ConfigEndorsement{}, fmt.Errorf("endorsement_ref must be a SHA-256 reference")
	}
	if _, err := decodeLowerHex("endorsement_ref", digest, sha256.Size); err != nil {
		return ConfigEndorsement{}, err
	}
	config, err := decodeCanonicalBase64("config_base64", c.Config)
	if err != nil {
		return ConfigEndorsement{}, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(c.Bundle), []byte("{")) {
		return ConfigEndorsement{}, fmt.Errorf("sigstore_bundle must be an object")
	}
	return ConfigEndorsement{Reference: c.Reference, Config: config, Bundle: c.Bundle}, nil
}

func (d *Document) uniqueReferenceValues(id, format string) (*CollateralEntry, error) {
	var selected *CollateralEntry
	for i := range d.collateral {
		entry := &d.collateral[i]
		if entry.ID != id && entry.Format != format {
			continue
		}
		if entry.ID != id || entry.Format != format || entry.Role != RoleReferenceValues {
			return nil, fmt.Errorf("conflicting collateral entry for %q", id)
		}
		if selected != nil {
			return nil, fmt.Errorf("duplicate collateral entry for %q", id)
		}
		selected = entry
	}
	if selected == nil {
		return nil, fmt.Errorf("%w: document carries no %q reference-values entry", ErrCollateralNotFound, id)
	}
	return selected, nil
}
