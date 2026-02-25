package client

import (
	"errors"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

var (
	ErrNoTLS              = errors.New("no TLS connection")
	ErrCertMismatch       = errors.New("certificate fingerprint mismatch")
	ErrNoValidCertificate = errors.New("no valid certificate")
)

type TLSBoundRoundTripper struct {
	ExpectedPublicKey string
}

var _ http.RoundTripper = &TLSBoundRoundTripper{}

func (t *TLSBoundRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if len(t.ExpectedPublicKey) == 0 {
		return nil, ErrNoValidCertificate
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	if resp.TLS == nil {
		resp.Body.Close()
		return nil, ErrNoTLS
	}

	certFP, err := attestation.ConnectionCertFP(*resp.TLS)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	if certFP != t.ExpectedPublicKey {
		resp.Body.Close()
		return nil, ErrCertMismatch
	}

	return resp, err
}
