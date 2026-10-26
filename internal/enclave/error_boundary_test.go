package enclave

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// The outermost verify error decides the SDK category, so a UsageError
// wrapped inside a VerificationError is still an attestation failure.
func TestFromVerifyClassifiesByOutermostVerifyError(t *testing.T) {
	usage := &verify.UsageError{Err: errors.New("bad input")}
	require.IsType(t, &ConfigurationError{}, fromVerify(usage))
	rejected := &verify.VerificationError{Err: usage}
	require.IsType(t, &AttestationError{}, fromVerify(rejected))
	require.ErrorIs(t, fromVerify(rejected), rejected)
	require.NoError(t, fromVerify(nil))
}

func TestTLSBindingUnsupportedDefaultTransport(t *testing.T) {
	// DefaultTransport is the configuration under test; keep this test serial.
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, transport := range []http.RoundTripper{roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported transport must not send the request")
		return nil, nil
	}), (*http.Transport)(nil)} {
		http.DefaultTransport = transport
		bound := &TLSBoundRoundTripper{ExpectedPublicKey: "key"}
		req, err := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		require.NoError(t, err)
		_, err = bound.RoundTrip(req)
		var config *ConfigurationError
		require.ErrorAs(t, err, &config)
		bound.CloseIdleConnections()
	}
}

func TestTLSClientPreservesTLSCategory(t *testing.T) {
	for _, trustCertificate := range []bool{true, false} {
		name := "untrusted certificate"
		if trustCertificate {
			name = "pin mismatch"
		}
		t.Run(name, func(t *testing.T) {
			server := newECDSATLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("TLS rejection must precede sending the request")
			}))
			defer server.Close()
			original := http.DefaultTransport
			transport := &http.Transport{}
			roots := x509.NewCertPool()
			if trustCertificate {
				roots.AddCert(server.Certificate())
			}
			transport.TLSClientConfig = &tls.Config{RootCAs: roots}
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
			s := &Handle{state: testEnclaveState(time.Now().Add(time.Hour), "wrong-pin")}
			var refreshes int
			s.verify = func() (*verify.Verification, error) {
				refreshes++
				return testState(time.Now().Add(time.Hour), "wrong-pin"), nil
			}
			hc, err := s.HTTPClient()
			require.NoError(t, err)
			_, err = hc.Get(server.URL)
			var attestation *AttestationError
			require.ErrorAs(t, err, &attestation)
			var httpError *url.Error
			require.ErrorAs(t, err, &httpError)
			require.Zero(t, refreshes, "standalone clients report rejection without replay")
			require.True(t, IsKeyRejection(err))
			if trustCertificate {
				require.ErrorIs(t, err, errCertMismatch)
			} else {
				var certificateError *tls.CertificateVerificationError
				require.ErrorAs(t, err, &certificateError)
			}
		})
	}
}
