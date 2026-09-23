package client

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

func TestVerifiedTransportKeysAllowTLSOnly(t *testing.T) {
	tls := document.CryptoMaterialItem{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "tls-fingerprint"}
	hpke := document.CryptoMaterialItem{ID: "hpke", Format: document.KeyX25519HPKEV1Format, Data: "hpke-key"}
	for _, tt := range []struct {
		name      string
		items     []document.CryptoMaterialItem
		wantHPKE  string
		wantError bool
	}{
		{"TLS only", []document.CryptoMaterialItem{tls}, "", false},
		{"TLS and HPKE", []document.CryptoMaterialItem{tls, hpke}, "hpke-key", false},
		{"missing TLS", []document.CryptoMaterialItem{hpke}, "", true},
		{"wrong TLS format", []document.CryptoMaterialItem{{ID: "tls", Format: "unexpected"}}, "", true},
		{"wrong HPKE format", []document.CryptoMaterialItem{tls, {ID: "hpke", Format: "unexpected"}}, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := &VerifiedDocumentV3{CryptoMaterial: tt.items}
			err := v.validateTransportKeys()
			if tt.wantError {
				var attestation *AttestationError
				require.ErrorAs(t, err, &attestation)
				return
			}
			require.NoError(t, err)
			tlsKey, err := v.TLSPublicKeyFP()
			require.NoError(t, err)
			require.Equal(t, tls.Data, tlsKey)
			hpkeKey, err := v.HPKEPublicKey()
			require.Equal(t, tt.wantHPKE, hpkeKey)
			if tt.wantHPKE == "" {
				require.Error(t, err, "explicit HPKE requests still require a key")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
