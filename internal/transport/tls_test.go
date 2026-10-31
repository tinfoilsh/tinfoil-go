package transport

import (
	"context"
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
	"reflect"
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
	var lacksKey *peerLacksKeyError
	require.ErrorAs(t, err, &lacksKey, "a pin mismatch must reach Transport as a key rejection")
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
	pinning := tlsMode{}
	transport, err := pinning.newRoundTripper(verifytest.New(verifytest.Fields{CryptoMaterial: []document.CryptoMaterialItem{
		{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: key},
	}}))
	require.NoError(t, err)
	pinned, ok := transport.(*TLSBoundRoundTripper)
	require.True(t, ok)
	require.Equal(t, key, pinned.key)

	_, err = pinning.newRoundTripper(&verify.Verification{})
	var attestation *errs.AttestationError
	require.ErrorAs(t, err, &attestation)
	require.ErrorIs(t, err, errNoTLSKey)
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

func TestTLSRefusesCustomTLSDialers(t *testing.T) {
	var received atomic.Int32
	server := newECDSATLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&tls.Dialer{Config: &tls.Config{RootCAs: roots}}).DialContext(ctx, network, addr)
	}
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for name, transport := range map[string]*http.Transport{
		"DialTLSContext": {TLSClientConfig: &tls.Config{RootCAs: roots}, DialTLSContext: dial},
		"DialTLS": {TLSClientConfig: &tls.Config{RootCAs: roots}, DialTLS: func(network, addr string) (net.Conn, error) {
			return dial(context.Background(), network, addr)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			http.DefaultTransport = transport
			// No certificate matches the pin, so only a skipped pin reaches
			// the server.
			h := enclave.NewTestHandle("enclave.example", testState(time.Now().Add(time.Hour), "wrong-pin"), nil)
			_, err := tlsClient(h).Post(server.URL, "text/plain", strings.NewReader("plaintext"))
			require.ErrorIs(t, err, errCustomTLSDialer)
			var config *errs.ConfigurationError
			require.ErrorAs(t, err, &config)
			require.Zero(t, received.Load(), "the request never reaches the server")
		})
	}
}

func TestTLSRefusesKeyLog(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{KeyLogWriter: io.Discard}}
	_, err := newTLSBoundRoundTripper("key")
	require.ErrorIs(t, err, errKeyLog)
	var config *errs.ConfigurationError
	require.ErrorAs(t, err, &config)
}

// TestPinnedTransportCopiesOnlyItsAllowlist sets every http.Transport field
// pinnedTransport doesn't refuse, and checks that only the allowlisted ones
// carry over. A field a Go release adds fails it until it is classified.
func TestPinnedTransportCopiesOnlyItsAllowlist(t *testing.T) {
	copied := map[string]bool{
		"Proxy": true, "OnProxyConnectResponse": true, "ProxyConnectHeader": true, "GetProxyConnectHeader": true,
		"DialContext": true, "Dial": true, "TLSHandshakeTimeout": true, "DisableKeepAlives": true,
		"DisableCompression": true, "MaxIdleConns": true, "MaxIdleConnsPerHost": true, "MaxConnsPerHost": true,
		"IdleConnTimeout": true, "ResponseHeaderTimeout": true, "ExpectContinueTimeout": true,
		"MaxResponseHeaderBytes": true, "WriteBufferSize": true, "ReadBufferSize": true,
		"ForceAttemptHTTP2": true, "HTTP2": true, "Protocols": true,
	}
	// pinnedTransport refuses the TLS dialers, builds its own TLSClientConfig,
	// and keeps TLSNextProto only as the empty map that turns off HTTP/2.
	refused := map[string]bool{"DialTLSContext": true, "DialTLS": true}
	built := map[string]bool{"TLSClientConfig": true, "TLSNextProto": true}

	base := reflect.ValueOf(&http.Transport{}).Elem()
	for _, field := range reflect.VisibleFields(base.Type()) {
		if !field.IsExported() {
			continue
		}
		name := field.Name
		require.True(t, copied[name] || refused[name] || built[name], "classify http.Transport.%s", name)
		if !refused[name] && !built[name] {
			base.FieldByIndex(field.Index).Set(nonZero(t, field.Type))
		}
	}
	caller := func(tls.ConnectionState) error { return nil }
	callerPeer := func([][]byte, [][]*x509.Certificate) error { return nil }
	roots := x509.NewCertPool()
	transport := base.Addr().Interface().(*http.Transport)
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{"h2": nil}
	transport.TLSClientConfig = &tls.Config{
		RootCAs: roots, VerifyConnection: caller, VerifyPeerCertificate: callerPeer,
		InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: "elsewhere.example",
		NextProtos: []string{"custom"}, ClientSessionCache: tls.NewLRUClientSessionCache(1),
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}, Rand: strings.NewReader(""),
		Time: time.Now, Certificates: []tls.Certificate{{}},
	}

	pinned, err := pinnedTransport(transport, "key")
	require.NoError(t, err)
	got := reflect.ValueOf(pinned).Elem()
	for name := range copied {
		require.False(t, got.FieldByName(name).IsZero(), "http.Transport.%s is copied", name)
	}
	require.Nil(t, pinned.TLSNextProto, "an installed protocol isn't copied")

	// The TLS config sets only its own fields and the caller's roots and
	// checks, whatever else the caller's config sets.
	config := reflect.ValueOf(pinned.TLSClientConfig).Elem()
	for _, field := range reflect.VisibleFields(config.Type()) {
		switch field.Name {
		case "MinVersion", "RootCAs", "VerifyConnection", "VerifyPeerCertificate":
			require.False(t, config.FieldByIndex(field.Index).IsZero(), "tls.Config.%s is set", field.Name)
		default:
			if field.IsExported() {
				require.True(t, config.FieldByIndex(field.Index).IsZero(), "tls.Config.%s isn't inherited", field.Name)
			}
		}
	}
	require.Equal(t, uint16(tls.VersionTLS12), pinned.TLSClientConfig.MinVersion)
	require.Same(t, roots, pinned.TLSClientConfig.RootCAs)
}

func TestPinnedTransportRunsTheCallersChecks(t *testing.T) {
	server := newECDSATLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the caller's rejection must precede sending the request")
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	key, err := verify.CertPubkeyFP(server.Certificate())
	require.NoError(t, err)
	rejection := errors.New("rejected by the caller")
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	for name, config := range map[string]*tls.Config{
		"VerifyConnection":      {RootCAs: roots, VerifyConnection: func(tls.ConnectionState) error { return rejection }},
		"VerifyPeerCertificate": {RootCAs: roots, VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return rejection }},
	} {
		t.Run(name, func(t *testing.T) {
			http.DefaultTransport = &http.Transport{TLSClientConfig: config}
			bound, err := newTLSBoundRoundTripper(key)
			require.NoError(t, err)
			defer bound.CloseIdleConnections()
			_, err = (&http.Client{Transport: bound}).Get(server.URL)
			require.ErrorIs(t, err, rejection, "the pin matches, so only the caller's check rejects")
		})
	}
}

func TestPinnedTransportKeepsHTTP2Off(t *testing.T) {
	pinned, err := pinnedTransport(&http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}, "key")
	require.NoError(t, err)
	require.NotNil(t, pinned.TLSNextProto)
	require.Empty(t, pinned.TLSNextProto)
}

// nonZero returns a non-zero value of typ, for the kinds of field
// http.Transport has.
func nonZero(t *testing.T, typ reflect.Type) reflect.Value {
	t.Helper()
	switch typ.Kind() {
	case reflect.Bool:
		return reflect.ValueOf(true).Convert(typ)
	case reflect.Int, reflect.Int64:
		v := reflect.New(typ).Elem()
		v.SetInt(1)
		return v
	case reflect.Func:
		return reflect.MakeFunc(typ, func([]reflect.Value) []reflect.Value {
			out := make([]reflect.Value, typ.NumOut())
			for i := range out {
				out[i] = reflect.Zero(typ.Out(i))
			}
			return out
		})
	case reflect.Pointer:
		return reflect.New(typ.Elem())
	case reflect.Map:
		m := reflect.MakeMap(typ)
		m.SetMapIndex(reflect.New(typ.Key()).Elem(), nonZero(t, typ.Elem()))
		return m
	case reflect.Slice:
		return reflect.MakeSlice(typ, 1, 1)
	}
	t.Fatalf("no non-zero value for %s", typ)
	return reflect.Value{}
}
