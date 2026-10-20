package enclave

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

func TestVerifiedTransportKeysAllowTLSOnly(t *testing.T) {
	tls := document.CryptoMaterialItem{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "tls-fingerprint"}
	hpke := document.CryptoMaterialItem{ID: "hpke", Format: document.KeyX25519HPKEV1Format, Data: "hpke-key"}
	for _, tt := range []struct {
		name     string
		items    []document.CryptoMaterialItem
		wantHPKE string
		wantErr  string
	}{
		{"TLS only", []document.CryptoMaterialItem{tls}, "", ""},
		{"TLS and HPKE", []document.CryptoMaterialItem{tls, hpke}, "hpke-key", ""},
		{"missing TLS", []document.CryptoMaterialItem{hpke}, "", `endorses no "tls" key`},
		{"wrong TLS format", []document.CryptoMaterialItem{{ID: "tls", Format: "unexpected"}}, "", `"tls" has format "unexpected"`},
		{"wrong HPKE format", []document.CryptoMaterialItem{tls, {ID: "hpke", Format: "unexpected"}}, "", `"hpke" has format "unexpected"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := &verify.Verification{CryptoMaterial: tt.items}
			err := validateTransportKeys(v)
			if tt.wantErr != "" {
				var attestation *AttestationError
				require.ErrorAs(t, err, &attestation)
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			tlsKey, ok := v.TLSPublicKeyFP()
			require.True(t, ok)
			require.Equal(t, tls.Data, tlsKey)
			hpkeKey, ok := v.HPKEPublicKey()
			require.Equal(t, tt.wantHPKE, hpkeKey)
			require.Equal(t, tt.wantHPKE != "", ok, "explicit HPKE requests still require a key")
		})
	}
}
