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

// Lifting the channel keys out of crypto_material by ID and format is the only
// real work this mapping does: binding a connection is what a caller has a
// verification for, and it should not have to repeat the lookup.
func TestVerificationLiftsChannelKeys(t *testing.T) {
	encoded, err := encode(sampleVerification())
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(encoded), &got))
	assert.Equal(t, "deadbeef", got["tls_public_key_fp"])
	assert.Equal(t, "cafebabe", got["hpke_public_key"])
	assert.Len(t, got["crypto_material"], 2, "lifted keys are still listed in full")
}

// A TLS-only enclave endorses no HPKE key. That has to be an absent field
// rather than a failed mapping, or such an enclave could not be used at all.
func TestVerificationOmitsMissingHPKE(t *testing.T) {
	v := sampleVerification()
	v.CryptoMaterial = v.CryptoMaterial[:1]

	encoded, err := encode(v)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(encoded), &got))
	assert.Equal(t, "deadbeef", got["tls_public_key_fp"])
	assert.NotContains(t, got, "hpke_public_key")
}

// time.Time cannot cross the FFI boundary, so the deadline a caller must honour
// is formatted here and parsed back on the other side.
func TestVerificationFormatsFreshnessDeadline(t *testing.T) {
	encoded, err := encode(sampleVerification())
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(encoded), &got))
	parsed, err := time.Parse(time.RFC3339Nano, got["freshness_expires_at"].(string))
	require.NoError(t, err)
	assert.True(t, parsed.Equal(sampleVerification().FreshnessExpiresAt))
}
