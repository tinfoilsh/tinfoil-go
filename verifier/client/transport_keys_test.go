package client

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

func TestVerifiedTransportKeysAllowTLSOnly(t *testing.T) {
	tls := envelope.CryptoMaterialItem{ID: "tls", Format: envelope.KeySPKIFPSHA256V1Format, Data: "tls-fingerprint"}
	hpke := envelope.CryptoMaterialItem{ID: "hpke", Format: envelope.KeyX25519HPKEV1Format, Data: "hpke-key"}
	for _, tt := range []struct {
		name      string
		items     []envelope.CryptoMaterialItem
		wantHPKE  string
		wantError bool
	}{
		{"TLS only", []envelope.CryptoMaterialItem{tls}, "", false},
		{"TLS and HPKE", []envelope.CryptoMaterialItem{tls, hpke}, "hpke-key", false},
		{"missing TLS", []envelope.CryptoMaterialItem{hpke}, "", true},
		{"wrong TLS format", []envelope.CryptoMaterialItem{{ID: "tls", Format: "unexpected"}}, "", true},
		{"wrong HPKE format", []envelope.CryptoMaterialItem{tls, {ID: "hpke", Format: "unexpected"}}, "", true},
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
