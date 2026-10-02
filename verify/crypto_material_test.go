package verify

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
)

func TestCryptoMaterialData(t *testing.T) {
	const futureFormat = "https://example.com/key/future/v1"
	v := &Verification{
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "aabb"},
			{ID: "workload", Format: futureFormat, Data: "010203"},
		},
	}
	data, err := v.CryptoMaterialData("workload", futureFormat)
	require.NoError(t, err)
	require.Equal(t, "010203", data)
	_, err = v.CryptoMaterialData("workload", document.KeySPKIV1Format)
	require.ErrorContains(t, err, "has format")
	_, err = v.CryptoMaterialData("missing", futureFormat)
	require.ErrorContains(t, err, "endorses no")
	_, err = (*Verification)(nil).CryptoMaterialData("workload", futureFormat)
	require.ErrorContains(t, err, "verification is required")
}
