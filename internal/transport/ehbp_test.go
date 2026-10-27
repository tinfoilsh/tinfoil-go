package transport

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

func hpkeVerification(key string) *verify.Verification {
	return verifytest.New(verifytest.Fields{CryptoMaterial: []document.CryptoMaterialItem{
		{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: key},
	}})
}

func TestEHBPRequiresHPKEKey(t *testing.T) {
	sealing := WithEHBP(nil, nil)
	_, err := sealing.build(&verify.Verification{})
	var attestation *errs.AttestationError
	require.ErrorAs(t, err, &attestation)
	require.ErrorContains(t, err, "use the TLS transport mode")

	_, err = sealing.build(hpkeVerification(""))
	require.ErrorAs(t, err, &attestation)
	require.ErrorContains(t, err, "HPKE public key")
}

func TestEHBPBuildsTransportForEachAttestedKey(t *testing.T) {
	for _, key := range []string{strings.Repeat("01", 32), strings.Repeat("02", 32)} {
		transport, err := WithEHBP(nil, nil).build(hpkeVerification(key))
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

func TestKeyTransportsRefuseRequestsTheyCantProtect(t *testing.T) {
	ehbp, tls := WithEHBP(nil, nil), TLS(nil)
	for _, tc := range []struct {
		name    string
		keyed   *Transport
		req     *http.Request
		refused error
	}{
		{"EHBP WebSocket upgrade", ehbp, websocketUpgrade(t, "https://enclave.example/v1/realtime"), errEHBPTunnel},
		{"EHBP CONNECT tunnel", ehbp, newRequest(t, http.MethodConnect, "https://enclave.example/", nil), errEHBPTunnel},
		{"EHBP request without a body", ehbp, newRequest(t, http.MethodGet, "https://enclave.example/v1/models", nil), nil},
		{"EHBP request with a body", ehbp, newRequest(t, http.MethodPost, "https://enclave.example/v1/chat/completions", strings.NewReader("{}")), nil},
		{"TLS WebSocket upgrade", tls, websocketUpgrade(t, "https://enclave.example/v1/realtime"), nil},
		{"TLS plaintext request", tls, newRequest(t, http.MethodGet, "http://enclave.example/v1/models", nil), errNoTLS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.keyed.check(tc.req)
			if tc.refused == nil {
				require.NoError(t, err)
				return
			}
			var config *errs.ConfigurationError
			require.ErrorAs(t, err, &config)
			require.ErrorIs(t, err, tc.refused)
		})
	}
}

func TestTransportChecksBeforeVerifying(t *testing.T) {
	h := enclave.NewTestHandle("enclave.example", nil, func() (*verify.Verification, error) {
		t.Error("verified for a request the transport refuses")
		return nil, errors.New("unreachable")
	})
	for _, tc := range []struct {
		keyed   *Transport
		req     *http.Request
		refused error
	}{
		{WithEHBP(nil, h), websocketUpgrade(t, "https://enclave.example/v1/realtime"), errEHBPTunnel},
		{TLS(h), newRequest(t, http.MethodGet, "http://enclave.example/v1/models", nil), errNoTLS},
	} {
		body := &closeTrackingBody{}
		tc.req.Body = body
		_, err := tc.keyed.RoundTrip(tc.req)
		require.ErrorIs(t, err, tc.refused)
		require.True(t, body.closed, "a refused request's body is closed")
	}
}

func TestEHBPRecognizesKeyConfigErrors(t *testing.T) {
	sealing := WithEHBP(nil, nil)
	require.True(t, sealing.keyRejected(ehbpidentity.NewKeyConfigError(errors.New("rotated"))))
	require.False(t, sealing.keyRejected(errors.New("connection reset")))
}

func TestEHBPSendsOverNext(t *testing.T) {
	key := strings.Repeat("01", 32)
	h := enclave.NewTestHandle("enclave.example", testState(time.Now().Add(time.Hour), key), nil)
	var sent []string
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		sent = append(sent, req.URL.Path)
		return testResponse(), nil
	})
	resp, err := WithEHBP(next, h).RoundTrip(newRequest(t, http.MethodGet, "https://enclave.example/v1/models", nil))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, []string{"/v1/models"}, sent)
}
