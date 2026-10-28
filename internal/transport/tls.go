package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

var (
	errNoTLS              = errors.New("TLS transport mode requires an HTTPS request")
	errCertMismatch       = errors.New("enclave certificate does not match the attested key; re-verify the enclave")
	errNoValidCertificate = errors.New("TLS transport mode requires a verified certificate fingerprint")
	// errNoTLSKey reports a verification with no TLS key to pin to.
	errNoTLSKey = fmt.Errorf("document endorses no %q key", document.CryptoMaterialIDTLS)
)

// TLS returns a Transport that pins each connection's leaf certificate to the
// TLS key h's current verification attests. It owns the connections, so it
// is the bottom of a stack. It refuses plaintext requests, which no pinned
// connection carries.
func TLS(h *enclave.Handle) *Transport {
	return &Transport{
		handle: h,
		build: func(v *verify.Verification) (http.RoundTripper, error) {
			key, ok := v.TLSPublicKeyFP()
			if !ok {
				return nil, &errs.AttestationError{Err: errNoTLSKey}
			}
			rt, err := newTLSBoundRoundTripper(key)
			if err != nil {
				// A nil *TLSBoundRoundTripper would be a non-nil RoundTripper.
				return nil, err
			}
			return rt, nil
		},
		keyRejected: isCertificateError,
		check: func(req *http.Request) error {
			if req.URL == nil || req.URL.Scheme != "https" {
				return &errs.ConfigurationError{Err: errNoTLS}
			}
			return nil
		},
	}
}

// TLSBoundRoundTripper sends requests over connections whose leaf
// certificate carries one attested TLS key.
type TLSBoundRoundTripper struct {
	key       string
	transport *http.Transport
}

var _ http.RoundTripper = &TLSBoundRoundTripper{}

// newTLSBoundRoundTripper pins connections to key, an attested TLS key
// fingerprint. It clones http.DefaultTransport's settings for timeouts,
// proxy, keep-alive, etc. and verifies key after normal TLS verification.
// VerifyConnection runs for direct HTTPS and HTTPS-over-CONNECT proxy
// connections; DialTLSContext only covers non-proxied HTTPS.
func newTLSBoundRoundTripper(key string) (*TLSBoundRoundTripper, error) {
	if key == "" {
		return nil, &errs.ConfigurationError{Err: errNoValidCertificate}
	}
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok || dt == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("TLS transport mode requires http.DefaultTransport to be a non-nil *http.Transport")}
	}
	dt = dt.Clone()

	tlsConfig := &tls.Config{}
	if dt.TLSClientConfig != nil {
		tlsConfig = dt.TLSClientConfig.Clone()
	}
	prevVerifyConnection := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if prevVerifyConnection != nil {
			if err := prevVerifyConnection(state); err != nil {
				return errs.WrapAttestation(err)
			}
		}

		certFP, err := verify.ConnectionCertFP(state)
		if err != nil {
			return &errs.AttestationError{Err: err}
		}
		if certFP != key {
			return &errs.AttestationError{Err: errCertMismatch}
		}
		return nil
	}

	dt.TLSClientConfig = tlsConfig
	return &TLSBoundRoundTripper{key: key, transport: dt}, nil
}

func (t *TLSBoundRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL == nil || r.URL.Scheme != "https" {
		return nil, &errs.ConfigurationError{Err: errNoTLS}
	}

	resp, err := t.transport.RoundTrip(r)
	if isCertificateError(err) {
		err = errs.WrapAttestation(err)
	}
	return resp, err
}

func (t *TLSBoundRoundTripper) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
}

func isCertificateError(err error) bool {
	var certInvalidErr x509.CertificateInvalidError
	var unknownAuthErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certVerifyErr *tls.CertificateVerificationError
	return errors.Is(err, errCertMismatch) ||
		errors.As(err, &certInvalidErr) || errors.As(err, &unknownAuthErr) ||
		errors.As(err, &hostnameErr) || errors.As(err, &certVerifyErr)
}
