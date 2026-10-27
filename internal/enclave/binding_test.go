package enclave

import (
	"errors"
	"io"
	"net/http"
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
	require.ErrorContains(t, err, "use the TLS binding")

	_, err = EHBP.Transport(hpkeVerification(""))
	require.ErrorAs(t, err, &attestation)
	require.ErrorContains(t, err, "HPKE public key")
}

func TestEHBPBindingBuildsTransportForEachAttestedKey(t *testing.T) {
	for _, key := range []string{strings.Repeat("01", 32), strings.Repeat("02", 32)} {
		transport, err := EHBP.Transport(hpkeVerification(key))
		require.NoError(t, err)
		require.NotNil(t, transport)
	}
}

type closeTrackingBody struct{ closed bool }

func (*closeTrackingBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *closeTrackingBody) Close() error           { b.closed = true; return nil }

func TestEHBPBindingRefusesUpgradesAndTunnels(t *testing.T) {
	var sent []string
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		sent = append(sent, req.Method+" "+req.URL.Path)
		return testResponse(), nil
	})
	transport, err := EHBP.Transport(hpkeVerification(strings.Repeat("01", 32)))
	require.NoError(t, err)

	upgrade, _ := http.NewRequest(http.MethodGet, "https://enclave.example/v1/realtime", nil)
	upgrade.Header.Set("Connection", "Upgrade")
	upgrade.Header.Set("Upgrade", "websocket")
	tunnel, _ := http.NewRequest(http.MethodConnect, "https://enclave.example/", nil)
	for _, req := range []*http.Request{upgrade, tunnel} {
		body := &closeTrackingBody{}
		req.Body = body
		_, err := transport.RoundTrip(req)
		var config *ConfigurationError
		require.ErrorAs(t, err, &config)
		require.ErrorIs(t, err, errEHBPTunnel)
		require.True(t, body.closed, "a refused request's body is closed")
	}
	require.Empty(t, sent, "nothing EHBP can't seal is sent")

	models, _ := http.NewRequest(http.MethodGet, "https://enclave.example/v1/models", nil)
	resp, err := transport.RoundTrip(models)
	require.NoError(t, err, "a request without a body is still allowed")
	resp.Body.Close()
	require.Equal(t, []string{"GET /v1/models"}, sent)
}

func TestEHBPBindingRecognizesKeyConfigErrors(t *testing.T) {
	require.True(t, EHBP.KeyRejected(ehbpidentity.NewKeyConfigError(errors.New("rotated"))))
	require.False(t, EHBP.KeyRejected(errors.New("connection reset")))
}
