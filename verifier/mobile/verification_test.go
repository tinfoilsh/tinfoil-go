package mobile

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

func sampleVerification() *client.VerifiedDocumentV3 {
	return &client.VerifiedDocumentV3{
		ConfigRepo:  "tinfoilsh/confidential-model-router",
		EnclaveHost: "inference.tinfoil.sh",
		Verifier:    client.SoftwareIdentity{Name: "tinfoil-go", Version: "0.15.7"},
		VerifiedAt:  "2026-09-26T12:00:00Z",
		CodeDigest:  "abc123",
		CodeTag:     "v1.2.3",
		CodeMeasurement: &measurement.Measurement{
			Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{"aa", "bb", "cc"},
		},
		EnclaveMeasurement: &measurement.Measurement{
			Type: measurement.TdxGuestV2, Registers: []string{"dd", "ee"},
		},
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "deadbeef"},
			{ID: "hpke", Format: document.KeyX25519HPKEV1Format, Data: "cafebabe"},
		},
		FreshnessExpiresAt: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
	}
}

// The JSON is a contract with callers that are never compiled against this
// package, so the keys are asserted here rather than left to the struct.
func TestVerificationJSONContract(t *testing.T) {
	encoded, err := encode(sampleVerification())
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(encoded), &got))

	assert.Equal(t, float64(VerificationSchemaVersion), got["schema_version"])
	assert.Equal(t, "tinfoilsh/confidential-model-router", got["config_repo"])
	assert.Equal(t, "inference.tinfoil.sh", got["enclave_host"])
	assert.Equal(t, "abc123", got["code_digest"])
	assert.Equal(t, "v1.2.3", got["code_tag"])
	assert.Equal(t, "2026-10-03T12:00:00Z", got["freshness_expires_at"])
	assert.Equal(t, "2026-09-26T12:00:00Z", got["verified_at"])

	// Channel keys are lifted out of crypto_material, and also still listed.
	assert.Equal(t, "deadbeef", got["tls_public_key_fp"])
	assert.Equal(t, "cafebabe", got["hpke_public_key"])
	assert.Len(t, got["crypto_material"], 2)

	verifier := got["verifier"].(map[string]any)
	assert.Equal(t, "tinfoil-go", verifier["name"])

	code := got["code_measurement"].(map[string]any)
	assert.Equal(t, string(measurement.SnpTdxMultiPlatformV1), code["type"])
	assert.Len(t, code["registers"], 3)
}

// A TLS-only enclave endorses no HPKE key; that must serialise as an absent
// field rather than failing the whole verification.
func TestVerificationJSONOmitsMissingHPKE(t *testing.T) {
	v := sampleVerification()
	v.CryptoMaterial = v.CryptoMaterial[:1]
	encoded, err := encode(v)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(encoded), &got))
	assert.Equal(t, "deadbeef", got["tls_public_key_fp"])
	assert.NotContains(t, got, "hpke_public_key")
}
