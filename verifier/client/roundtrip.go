package client

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
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
		// then verify the attested public key after normal TLS verification.
		// VerifyConnection runs for direct HTTPS and HTTPS-over-CONNECT proxy
		// connections; DialTLSContext only covers non-proxied HTTPS.
		dt := http.DefaultTransport.(*http.Transport).Clone()

		tlsConfig := &tls.Config{}
		if dt.TLSClientConfig != nil {
			tlsConfig = dt.TLSClientConfig.Clone()
		}
		prevVerifyConnection := tlsConfig.VerifyConnection
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if prevVerifyConnection != nil {
				if err := prevVerifyConnection(state); err != nil {
					return err
				}
			}

			certFP, err := ConnectionCertFP(state)
			if err != nil {
				return err
			}
			if certFP != t.ExpectedPublicKey {
				return ErrCertMismatch
			}
			return nil
		}

		dt.TLSClientConfig = tlsConfig
		t.transport = dt
	})
	return t.transport
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

// KeyFP returns the fingerprint of a given ECDSA public key
func KeyFP(publicKey *ecdsa.PublicKey) string {
	bytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}

// CertPubkeyFP returns the fingerprint of the public key of a given certificate
func CertPubkeyFP(cert *x509.Certificate) (string, error) {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}

	return KeyFP(pubKey), nil
}

// ConnectionCertFP gets the KeyFP of the public key of a TLS connection state
func ConnectionCertFP(c tls.ConnectionState) (string, error) {
	if len(c.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificates")
	}
	cert := c.PeerCertificates[0]
	return CertPubkeyFP(cert)
}
