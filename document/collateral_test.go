package document

import (
	"encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func TestCollateralFormatRoundTrip(t *testing.T) {
	for _, format := range []string{"", collateral.FormatV2, collateral.FormatV3} {
		t.Run(format, func(t *testing.T) {
			nonce := testNonce()
			data, err := Build(BuildInput{Nonce: nonce, CollateralFormat: format}, fakeQuote(SEVSNPReportV1Format, []byte("quote"), nil))
			require.NoError(t, err)
			doc, err := Parse(data, nonce)
			require.NoError(t, err)
			if format == collateral.FormatV3 {
				require.Equal(t, format, doc.CollateralFormat())
			} else {
				require.Equal(t, collateral.FormatV2, doc.CollateralFormat())
				require.NotContains(t, string(data), "collateral_format")
			}
		})
	}
}

func TestRejectsIncompatibleCollateralFormat(t *testing.T) {
	legacy := collateral.Entry{ID: "code", Role: collateral.RoleReferenceValues, Format: collateral.SigstoreCodeV1Format, Data: []byte(`{"digest":"digest","sigstore_bundle":{}}`)}
	config := collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigEndorsementV1Format, Data: []byte(`{"endorsement_ref":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","config_base64":"eA==","sigstore_bundle":{}}`)}
	for _, tc := range []struct {
		name, format, want string
		entries            []collateral.Entry
	}{
		{name: "unknown", format: "unknown", want: "unsupported collateral format"},
		{name: "legacy code in v3", format: collateral.FormatV3, entries: []collateral.Entry{legacy}, want: "legacy code collateral"},
		{name: "config without version", entries: []collateral.Entry{config}, want: "config and runtime collateral require"},
		{name: "config in v2", format: collateral.FormatV2, entries: []collateral.Entry{config}, want: "config and runtime collateral require"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nonce := testNonce()
			_, err := Build(BuildInput{Nonce: nonce, CollateralFormat: tc.format, Collateral: tc.entries}, func([64]byte) (string, []byte, error) {
				t.Fatal("invalid collateral must be rejected before requesting a quote")
				return "", nil, nil
			})
			require.ErrorContains(t, err, tc.want)
			data, err := Build(BuildInput{Nonce: nonce}, fakeQuote(SEVSNPReportV1Format, []byte("quote"), nil))
			require.NoError(t, err)
			var raw rawDocument
			require.NoError(t, json.Unmarshal(data, &raw))
			raw.CollateralFormat, raw.Collateral = tc.format, tc.entries
			data, err = json.Marshal(raw)
			require.NoError(t, err)
			_, err = Parse(data, nonce)
			require.ErrorContains(t, err, tc.want)
		})
	}
}
