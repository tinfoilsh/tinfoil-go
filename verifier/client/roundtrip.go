package client

import (
	"crypto/tls"
	"errors"
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
