package document

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigEndorsement(t *testing.T) {
	config := []byte("cvm-version: 1.0.0\n")
	reference := "sha256:" + strings.Repeat("ab", 32)
	data, err := json.Marshal(configCollateral{
		Reference: reference,
		Config:    base64.StdEncoding.EncodeToString(config),
		Bundle:    []byte(`{"mediaType":"test"}`),
	})
	require.NoError(t, err)
	entry := CollateralEntry{ID: ConfigCollateralID, Role: RoleReferenceValues, Format: CollateralConfigEndorsementV1Format, Data: data}
	doc := &Document{collateral: []CollateralEntry{entry}}
	got, err := doc.ConfigEndorsement()
	require.NoError(t, err)
	require.Equal(t, reference, got.Reference)
	require.Equal(t, config, got.Config)
	require.JSONEq(t, `{"mediaType":"test"}`, string(got.Bundle))

	for name, mutate := range map[string]func(*Document){
		"missing":      func(d *Document) { d.collateral = nil },
		"wrong role":   func(d *Document) { d.collateral[0].Role = RoleEndorsement },
		"wrong format": func(d *Document) { d.collateral[0].Format = CollateralSigstoreCodeV1Format },
		"wrong id":     func(d *Document) { d.collateral[0].ID = "other" },
		"duplicate":    func(d *Document) { d.collateral = append(d.collateral, entry) },
		"ambiguous format": func(d *Document) {
			other := entry
			other.ID = "other"
			d.collateral = append(d.collateral, other)
		},
		"noncanonical base64": func(d *Document) {
			d.collateral[0].Data = []byte(strings.Replace(string(data), `"config_base64":"`, `"config_base64":"\n`, 1))
		},
		"bad reference": func(d *Document) {
			d.collateral[0].Data = []byte(strings.Replace(string(data), reference, "sha256:bad", 1))
		},
		"unknown member": func(d *Document) {
			d.collateral[0].Data = append([]byte(`{"unknown":true,`), data[1:]...)
		},
		"duplicate member": func(d *Document) {
			d.collateral[0].Data = append([]byte(`{"endorsement_ref":"ignored",`), data[1:]...)
		},
		"missing bundle": func(d *Document) {
			d.collateral[0].Data = []byte(strings.Replace(string(data), `{"mediaType":"test"}`, "null", 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := &Document{collateral: []CollateralEntry{entry}}
			mutate(doc)
			_, err := doc.ConfigEndorsement()
			require.Error(t, err)
		})
	}
}
