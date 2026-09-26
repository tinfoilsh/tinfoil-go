package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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

func TestRequestPreservesTLSCategoryAndMobilePrefix(t *testing.T) {
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
			s := &SecureClient{state: testEnclaveState(time.Now().Add(time.Hour), "wrong-pin")}
			var refreshes int
			s.verify = func() (*VerifiedDocumentV3, error) {
				refreshes++
				return testState(time.Now().Add(time.Hour), "wrong-pin"), nil
			}
			_, err := s.Request(http.MethodGet, server.URL, "", nil)
			var attestation *AttestationError
			require.ErrorAs(t, err, &attestation)
			var httpError *url.Error
			require.ErrorAs(t, err, &httpError)
			require.True(t, strings.HasPrefix(err.Error(), "attestation error: "))
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

func TestMobileErrorPreservesCategoriesAndNativeFailures(t *testing.T) {
	for _, category := range []Error{&ConfigurationError{Err: errors.New("bad input")}, &FetchError{Err: errors.New("unavailable")}} {
		wrapped := &url.Error{Op: "Get", URL: "https://enclave.example", Err: category}
		err := mobileError(wrapped)
		require.ErrorIs(t, err, wrapped)
		var actual Error
		require.ErrorAs(t, err, &actual)
		require.Same(t, category, actual)
		prefix, _, _ := strings.Cut(category.Error(), ": ")
		require.True(t, strings.HasPrefix(err.Error(), prefix+": "))
	}
	native := errors.New("connection refused")
	require.Same(t, native, mobileError(native))
}
