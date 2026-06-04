package client

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
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

	client := &http.Client{
		Transport: &TLSBoundRoundTripper{ExpectedPublicKey: "not-the-attested-key"},
	}
	resp, err := client.Get(target.URL)
	if resp != nil {
		resp.Body.Close()
	}

	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertMismatch), "got %v", err)
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

	certFP, err := attestation.CertPubkeyFP(target.Certificate())
	require.NoError(t, err)

	client := &http.Client{
		Transport: &TLSBoundRoundTripper{ExpectedPublicKey: certFP},
	}
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
