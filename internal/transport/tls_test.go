package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

func TestTLSBoundRoundTripperRejectsPinnedMismatchThroughHTTPSProxy(t *testing.T) {
	var reached atomic.Bool
	target := newECDSATLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	proxy := newConnectProxy()
	defer proxy.Close()
	withDefaultProxyTransport(t, target, proxy)

	bound, err := newTLSBoundRoundTripper("not-the-attested-key")
	require.NoError(t, err)
	client := &http.Client{Transport: bound}
	resp, err := client.Get(target.URL)
	if resp != nil {
		resp.Body.Close()
	}

	require.Error(t, err)
	require.True(t, errors.Is(err, errCertMismatch), "got %v", err)
	var attestation *errs.AttestationError
	require.ErrorAs(t, err, &attestation)
	require.True(t, isCertificateError(err), "typed errors must preserve TLS recovery")
	require.False(t, reached.Load(), "request must not reach the server after a pin mismatch")
}

func TestTLSBoundRoundTripperAllowsPinnedHTTPSThroughProxy(t *testing.T) {
	var reached atomic.Bool
	target := newECDSATLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	proxy := newConnectProxy()
	defer proxy.Close()
	withDefaultProxyTransport(t, target, proxy)

	certFP, err := verify.CertPubkeyFP(target.Certificate())
	require.NoError(t, err)

	bound, err := newTLSBoundRoundTripper(certFP)
	require.NoError(t, err)
	client := &http.Client{Transport: bound}
	resp, err := client.Get(target.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.True(t, reached.Load())
}

func withDefaultProxyTransport(t *testing.T, target *httptest.Server, proxy *httptest.Server) {
	t.Helper()

	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(target.Certificate())

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}

	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = original
	})
}

func newECDSATLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  privateKey,
			Leaf:        leaf,
		}},
	}
	server.StartTLS()
	return server
}

func newConnectProxy() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}

		targetConn, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			targetConn.Close()
			http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		proxyConn, _, err := hijacker.Hijack()
		if err != nil {
			targetConn.Close()
			return
		}

		if _, err := proxyConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			proxyConn.Close()
			targetConn.Close()
			return
		}

		go tunnel(proxyConn, targetConn)
		go tunnel(targetConn, proxyConn)
	}))
}

func tunnel(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func TestTLSPinsAttestedKey(t *testing.T) {
	key := strings.Repeat("ab", 32)
	pinning := TLS(nil)
	transport, err := pinning.build(verifytest.New(verifytest.Fields{CryptoMaterial: []document.CryptoMaterialItem{
		{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: key},
	}}))
	require.NoError(t, err)
	pinned, ok := transport.(*TLSBoundRoundTripper)
	require.True(t, ok)
	require.Equal(t, key, pinned.key)

	_, err = pinning.build(&verify.Verification{})
	var attestation *errs.AttestationError
	require.ErrorAs(t, err, &attestation)
	require.ErrorIs(t, err, errNoTLSKey)

	require.True(t, pinning.keyRejected(&errs.AttestationError{Err: errCertMismatch}))
	require.False(t, pinning.keyRejected(errors.New("connection reset")))
}

func TestTLSUnsupportedDefaultTransport(t *testing.T) {
	// DefaultTransport is the configuration under test; keep this test serial.
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, transport := range []http.RoundTripper{roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported transport must not send the request")
		return nil, nil
	}), (*http.Transport)(nil)} {
		http.DefaultTransport = transport
		h := enclave.NewTestHandle("enclave.example", testState(time.Now().Add(time.Hour), "key"), nil)
		pinning := TLS(h)
		req, err := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		require.NoError(t, err)
		_, err = pinning.RoundTrip(req)
		var config *errs.ConfigurationError
		require.ErrorAs(t, err, &config)
		pinning.CloseIdleConnections()
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
			var refreshes int
			s := enclave.NewTestHandle("enclave.example", testState(time.Now().Add(time.Hour), "wrong-pin"), func() (*verify.Verification, error) {
				refreshes++
				return testState(time.Now().Add(time.Hour), "wrong-pin"), nil
			})
			_, err := tlsClient(s).Get(server.URL)
			var attestation *errs.AttestationError
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
