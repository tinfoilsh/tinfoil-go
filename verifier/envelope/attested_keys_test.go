package envelope

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Public-only vectors are shared with sdk-flywheel/v3/attested-keys-vectors.json.
// These check envelope binding, not hardware quote authentication.
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
			pub, err := hex.DecodeString(v.Item.Data)
			require.NoError(t, err)
			key, err := x509.ParsePKIXPublicKey(pub)
			require.NoError(t, err)
			switch v.Algorithm {
			case "ecdsa-p256":
				require.IsType(t, &ecdsa.PublicKey{}, key)
				require.Equal(t, elliptic.P256(), key.(*ecdsa.PublicKey).Curve)
			case "ed25519":
				require.IsType(t, ed25519.PublicKey{}, key)
			case "x25519":
				require.IsType(t, &ecdh.PublicKey{}, key)
				require.Equal(t, ecdh.X25519(), key.(*ecdh.PublicKey).Curve())
			default:
				t.Fatalf("unexpected vector algorithm %q", v.Algorithm)
			}
			nonce, err := hex.DecodeString(v.Nonce)
			require.NoError(t, err)
			cm, err := base64.StdEncoding.DecodeString(v.CryptoMaterial)
			require.NoError(t, err)
			de, err := base64.StdEncoding.DecodeString(v.DeviceEvidence)
			require.NoError(t, err)
			ch, dh := sha256.Sum256(cm), sha256.Sum256(de)
			require.Equal(t, v.CryptoHash, hex.EncodeToString(ch[:]))
			require.Equal(t, v.DeviceHash, hex.EncodeToString(dh[:]))
			rd, err := ComputeReportData(nonce, ch[:], dh[:])
			require.NoError(t, err)
			require.Equal(t, v.ReportData, hex.EncodeToString(rd[:]))
			doc, _ := buildTestDocument(t, nonce)
			doc.CryptoMaterial, doc.DeviceEvidence = v.CryptoMaterial, v.DeviceEvidence
			doc.CPUEvidence.Endorsed = EndorsedHashes{CryptoMaterialHash: v.CryptoHash, DeviceEvidenceHash: v.DeviceHash}
			doc.Challenge.ReportData = v.ReportData
			encoded, err := json.Marshal(doc)
			require.NoError(t, err)
			parsed, _, err := Check(encoded, nonce)
			require.NoError(t, err)
			require.Equal(t, []CryptoMaterialItem{v.Item}, parsed.CryptoMaterialItems())
			for _, field := range []string{"id", "format", "data"} {
				t.Run("tamper-"+field, func(t *testing.T) {
					tampered := mutateCryptoSection(t, encoded, func(section []byte) []byte {
						var cm CryptoMaterialSection
						require.NoError(t, json.Unmarshal(section, &cm))
						switch field {
						case "id":
							cm.Items[0].ID += "-other"
						case "format":
							cm.Items[0].Format += "-other"
						case "data":
							cm.Items[0].Data += "00"
						}
						out, err := json.Marshal(cm)
						require.NoError(t, err)
						return out
					})
					_, _, err := Check(tampered, nonce)
					require.ErrorContains(t, err, "crypto_material hash")
				})
			}
		})
	}
}
