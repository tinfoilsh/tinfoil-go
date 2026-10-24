package enclave

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

func hpkeVerification(key string) *verify.Verification {
	return verifytest.New(verifytest.Fields{CryptoMaterial: []document.CryptoMaterialItem{
		{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: key},
	}})
}

func TestTLSBindingPinsAttestedKey(t *testing.T) {
	key := strings.Repeat("ab", 32)
	transport, err := TLS.Transport(verifytest.New(verifytest.Fields{CryptoMaterial: []document.CryptoMaterialItem{
		{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: key},
	}}))
	require.NoError(t, err)
	pinned, ok := transport.(*TLSBoundRoundTripper)
	require.True(t, ok)
	require.Equal(t, key, pinned.ExpectedPublicKey)

	_, err = TLS.Transport(&verify.Verification{})
	var attestation *AttestationError
	require.ErrorAs(t, err, &attestation)
	require.ErrorIs(t, err, errNoTLSKey)

	require.True(t, TLS.KeyRejected(&AttestationError{Err: errCertMismatch}))
	require.False(t, TLS.KeyRejected(errors.New("connection reset")))
}

func TestEHBPBindingRequiresHPKEKey(t *testing.T) {
	_, err := EHBP.Transport(&verify.Verification{})
	var attestation *AttestationError
	require.ErrorAs(t, err, &attestation)
	require.ErrorContains(t, err, "WithTransport(TransportTLS)")

	_, err = EHBP.Transport(hpkeVerification(""))
	require.ErrorAs(t, err, &attestation)
	require.ErrorContains(t, err, "HPKE public key")
}

func TestEHBPBindingSealsToEachAttestedKey(t *testing.T) {
	for _, key := range []string{strings.Repeat("01", 32), strings.Repeat("02", 32)} {
		transport, err := EHBP.Transport(hpkeVerification(key))
		require.NoError(t, err)
		require.NotNil(t, transport)
	}

	require.True(t, EHBP.KeyRejected(ehbpidentity.NewKeyConfigError(errors.New("rotated"))))
	require.False(t, EHBP.KeyRejected(errors.New("connection reset")))
}
