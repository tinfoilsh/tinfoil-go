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

func newRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	require.NoError(t, err)
	return req
}

func websocketUpgrade(t *testing.T, url string) *http.Request {
	req := newRequest(t, http.MethodGet, url, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	return req
}

func TestBindingsRefuseRequestsTheyCantProtect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding Binding
		req     *http.Request
		refused error
	}{
		{"EHBP WebSocket upgrade", EHBP, websocketUpgrade(t, "https://enclave.example/v1/realtime"), errEHBPTunnel},
		{"EHBP CONNECT tunnel", EHBP, newRequest(t, http.MethodConnect, "https://enclave.example/", nil), errEHBPTunnel},
		{"EHBP request without a body", EHBP, newRequest(t, http.MethodGet, "https://enclave.example/v1/models", nil), nil},
		{"EHBP request with a body", EHBP, newRequest(t, http.MethodPost, "https://enclave.example/v1/chat/completions", strings.NewReader("{}")), nil},
		{"TLS WebSocket upgrade", TLS, websocketUpgrade(t, "https://enclave.example/v1/realtime"), nil},
		{"TLS plaintext request", TLS, newRequest(t, http.MethodGet, "http://enclave.example/v1/models", nil), errNoTLS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.binding.Check(tc.req)
			if tc.refused == nil {
				require.NoError(t, err)
				return
			}
			var config *ConfigurationError
			require.ErrorAs(t, err, &config)
			require.ErrorIs(t, err, tc.refused)
		})
	}
}

func TestBoundTransportChecksBeforeVerifying(t *testing.T) {
	h := &Handle{verify: func() (*verify.Verification, error) {
		t.Error("verified for a request the binding refuses")
		return nil, errors.New("unreachable")
	}}
	for _, tc := range []struct {
		binding Binding
		req     *http.Request
		refused error
	}{
		{EHBP, websocketUpgrade(t, "https://enclave.example/v1/realtime"), errEHBPTunnel},
		{TLS, newRequest(t, http.MethodGet, "http://enclave.example/v1/models", nil), errNoTLS},
	} {
		bound, err := NewBoundTransport(h, tc.binding)
		require.NoError(t, err)
		body := &closeTrackingBody{}
		tc.req.Body = body
		_, err = bound.RoundTrip(tc.req)
		require.ErrorIs(t, err, tc.refused)
		require.True(t, body.closed, "a refused request's body is closed")
	}
}

func TestEHBPBindingRecognizesKeyConfigErrors(t *testing.T) {
	require.True(t, EHBP.KeyRejected(ehbpidentity.NewKeyConfigError(errors.New("rotated"))))
	require.False(t, EHBP.KeyRejected(errors.New("connection reset")))
}
