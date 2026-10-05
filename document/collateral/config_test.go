package collateral

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func configEntry(data string) Entry {
	return Entry{ID: ConfigID, Role: RoleReferenceValues, Format: ConfigEndorsementV1Format, Data: []byte(data)}
}

func TestDecodeConfigEndorsement(t *testing.T) {
	config := "cvm-version: v1.0.0\ncpus: 4\n"
	set, err := Decode([]Entry{configEntry(
		`{"config_base64":"` + base64.StdEncoding.EncodeToString([]byte(config)) + `","sigstore_bundle":{"a":1}}`)})
	require.NoError(t, err)
	require.NotNil(t, set.Config)
	assert.Equal(t, config, string(set.Config.Config))
	assert.JSONEq(t, `{"a":1}`, string(set.Config.Bundle))

	// A clone must not share the decoded bytes with the set.
	clone := set.Config.Clone()
	clone.Config[0] = 'X'
	clone.Bundle[0] = ' '
	assert.Equal(t, config, string(set.Config.Config))
	assert.JSONEq(t, `{"a":1}`, string(set.Config.Bundle))
}

func TestDecodeConfigEndorsementRejections(t *testing.T) {
	config := base64.StdEncoding.EncodeToString([]byte("x"))
	for _, tt := range []struct {
		name, data, wantErr string
	}{
		{"no bundle", `{"config_base64":"` + config + `"}`, "missing sigstore_bundle"},
		{"null bundle", `{"config_base64":"` + config + `","sigstore_bundle":null}`, "missing sigstore_bundle"},
		{"no config", `{"sigstore_bundle":{"a":1}}`, "carries no config"},
		{"empty config", `{"config_base64":"","sigstore_bundle":{"a":1}}`, "carries no config"},
		{"not base64", `{"config_base64":"!!","sigstore_bundle":{"a":1}}`, "config_base64"},
		{"unknown member", `{"config_base64":"` + config + `","sigstore_bundle":{"a":1},"digest":"x"}`, "unknown object member"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode([]Entry{configEntry(tt.data)})
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
