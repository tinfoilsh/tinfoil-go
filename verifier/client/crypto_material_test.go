package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

func TestCryptoMaterialData(t *testing.T) {
	const futureFormat = "https://example.com/key/future/v1"
	deadline := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	v := &VerifiedDocumentV3{
		FreshnessExpiresAt: deadline,
		CryptoMaterial: []envelope.CryptoMaterialItem{
			{ID: "tls", Format: envelope.KeySPKIFPSHA256V1Format, Data: "aabb"},
			{ID: "workload", Format: futureFormat, Data: "010203"},
		},
	}
	data, err := v.CryptoMaterialData("workload", futureFormat)
	require.NoError(t, err)
	require.Equal(t, "010203", data)
	// Lookup neither extends the evidence deadline nor invents a new format.
	require.Equal(t, deadline, v.FreshnessExpiresAt)
	_, err = v.CryptoMaterialData("workload", envelope.KeySPKIV1Format)
	require.ErrorContains(t, err, "has format")
	_, err = v.CryptoMaterialData("missing", futureFormat)
	require.ErrorContains(t, err, "endorses no")
	_, err = v.CryptoMaterialData("WORKLOAD", futureFormat)
	require.Error(t, err)
	_, err = (*VerifiedDocumentV3)(nil).CryptoMaterialData("workload", futureFormat)
	require.ErrorContains(t, err, "no verified document")
	data, err = v.TLSPublicKeyFP()
	require.NoError(t, err)
	require.Equal(t, "aabb", data)
}
