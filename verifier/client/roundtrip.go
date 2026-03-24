package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

var (
	ErrNoTLS              = errors.New("no TLS connection")
	ErrCertMismatch       = errors.New("certificate fingerprint mismatch")
	ErrNoValidCertificate = errors.New("no valid certificate")
)

type TLSBoundRoundTripper struct {
	ExpectedPublicKey string
	once              sync.Once
	transport         *http.Transport
}

var _ http.RoundTripper = &TLSBoundRoundTripper{}

func (t *TLSBoundRoundTripper) getTransport() *http.Transport {
	t.once.Do(func() {
		// Clone DefaultTransport settings for timeouts, proxy, keep-alive, etc.
		// then override DialTLSContext to inject our certificate pinning check.
		dt := http.DefaultTransport.(*http.Transport).Clone()
		dt.DialTLSContext = t.dialTLSContext
		t.transport = dt
	})
	return t.transport
}

// dialTLSContext performs the TLS handshake and verifies the certificate
// fingerprint BEFORE any HTTP request data is sent over the connection.
func (t *TLSBoundRoundTripper) dialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 30 * time.Second},
	}
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, ErrNoTLS
	}

	certFP, err := attestation.ConnectionCertFP(tlsConn.ConnectionState())
	if err != nil {
		conn.Close()
		return nil, err
	}
	if certFP != t.ExpectedPublicKey {
		conn.Close()
		return nil, ErrCertMismatch
	}

	return conn, nil
}

func (t *TLSBoundRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if len(t.ExpectedPublicKey) == 0 {
		return nil, ErrNoValidCertificate
	}

	if r.URL == nil || r.URL.Scheme != "https" {
		return nil, ErrNoTLS
	}

	return t.getTransport().RoundTrip(r)
}
