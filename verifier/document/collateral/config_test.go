package collateral

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
	entry := Entry{ID: ConfigID, Role: RoleReferenceValues, Format: ConfigEndorsementV1Format, Data: data}
	set, err := Decode([]Entry{entry})
	require.NoError(t, err)
	got := set.Config
	require.NotNil(t, got)
	require.Equal(t, reference, got.Reference)
	require.Equal(t, config, got.Config)
	require.JSONEq(t, `{"mediaType":"test"}`, string(got.Bundle))

	for name, mutate := range map[string]func(*[]Entry){
		"wrong role":   func(entries *[]Entry) { (*entries)[0].Role = RoleEndorsement },
		"wrong format": func(entries *[]Entry) { (*entries)[0].Format = SigstoreCodeV1Format },
		"wrong id":     func(entries *[]Entry) { (*entries)[0].ID = "other" },
		"duplicate":    func(entries *[]Entry) { *entries = append(*entries, entry) },
		"ambiguous format": func(entries *[]Entry) {
			other := entry
			other.ID = "other"
			*entries = append(*entries, other)
		},
		"noncanonical base64": func(entries *[]Entry) {
			(*entries)[0].Data = []byte(strings.Replace(string(data), `"config_base64":"`, `"config_base64":"\n`, 1))
		},
		"bad reference": func(entries *[]Entry) {
			(*entries)[0].Data = []byte(strings.Replace(string(data), reference, "sha256:bad", 1))
		},
		"unknown member": func(entries *[]Entry) {
			(*entries)[0].Data = append([]byte(`{"unknown":true,`), data[1:]...)
		},
		"duplicate member": func(entries *[]Entry) {
			(*entries)[0].Data = append([]byte(`{"endorsement_ref":"ignored",`), data[1:]...)
		},
		"missing bundle": func(entries *[]Entry) {
			(*entries)[0].Data = []byte(strings.Replace(string(data), `{"mediaType":"test"}`, "null", 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			entries := []Entry{entry}
			mutate(&entries)
			_, err := Decode(entries)
			require.Error(t, err)
		})
	}
}
