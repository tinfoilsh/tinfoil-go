package verify

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

func TestCryptoMaterialData(t *testing.T) {
	const futureFormat = "https://example.com/key/future/v1"
	v := &Verification{
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "aabb"},
			{ID: "workload", Format: futureFormat, Data: "010203"},
		},
	}
	data, ok := v.CryptoMaterialData("workload", futureFormat)
	require.True(t, ok)
	require.Equal(t, "010203", data)
	_, ok = v.CryptoMaterialData("workload", document.KeySPKIV1Format)
	require.False(t, ok, "an item in another format is not the one asked for")
	_, ok = v.CryptoMaterialData("missing", futureFormat)
	require.False(t, ok)
	_, ok = (*Verification)(nil).CryptoMaterialData("workload", futureFormat)
	require.False(t, ok, "a nil verification endorses nothing")
}
