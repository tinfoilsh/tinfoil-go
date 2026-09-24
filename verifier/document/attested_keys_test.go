package document

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Public-only vectors are shared with sdk-flywheel/v3/attested-keys-vectors.json.
// Check must accept and preserve key formats the SDK does not interpret.
func TestAttestedKeyEnvelopeVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/attested-keys-vectors.json")
	require.NoError(t, err)
	var vectors []struct {
		Algorithm      string             `json:"algorithm"`
		Item           CryptoMaterialItem `json:"item"`
		Nonce          string             `json:"nonce"`
		CryptoMaterial string             `json:"crypto_material"`
		DeviceEvidence string             `json:"device_evidence"`
		CryptoHash     string             `json:"crypto_material_hash"`
		DeviceHash     string             `json:"device_evidence_hash"`
		ReportData     string             `json:"report_data"`
	}
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.Len(t, vectors, 3)
	for _, v := range vectors {
		t.Run(v.Algorithm, func(t *testing.T) {
			nonce, err := hex.DecodeString(v.Nonce)
			require.NoError(t, err)
			doc, _ := buildTestDocument(t, nonce)
			doc.CryptoMaterial, doc.DeviceEvidence = v.CryptoMaterial, v.DeviceEvidence
			doc.CPUEvidence.Endorsed = EndorsedHashes{CryptoMaterialHash: v.CryptoHash, DeviceEvidenceHash: v.DeviceHash}
			doc.Challenge.ReportData = v.ReportData
			encoded, err := json.Marshal(doc)
			require.NoError(t, err)
			parsed, _, err := Check(encoded, nonce)
			require.NoError(t, err)
			require.Equal(t, KeySPKIV1Format, v.Item.Format)
			require.Equal(t, []CryptoMaterialItem{v.Item}, parsed.CryptoMaterialItems())
		})
	}
}
