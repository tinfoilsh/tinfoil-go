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
	// errCustomTLSDialer reports a TLS dialer, which Go would use in place of
	// the handshake that checks the pin.
	errCustomTLSDialer = errors.New("TLS transport mode can't pin connections that http.DefaultTransport's DialTLSContext or DialTLS makes; remove the TLS dialer or use the EHBP transport mode")
	// errKeyLog reports a TLS key log, which would expose pinned connections.
	errKeyLog = errors.New("TLS transport mode refuses http.DefaultTransport's TLSClientConfig.KeyLogWriter, which would expose the session keys of pinned connections")
)

// TLS returns a Transport that pins each connection's leaf certificate to the
// TLS key e's current verification attests. It owns the connections, so it
// is the bottom of a stack. It refuses plaintext requests, which no pinned
// connection carries.
func TLS(e *enclave.Enclave) *Transport {
	return &Transport{enclave: e, mode: tlsMode{}}
}

// tlsMode pins connections to the attested TLS key.
type tlsMode struct{}

func (tlsMode) validateRequest(req *http.Request) error {
	if req.URL == nil || req.URL.Scheme != "https" {
		return &errs.ConfigurationError{Err: errNoTLS}
	}
	return nil
}

func (tlsMode) newRoundTripper(v *verify.Verification) (http.RoundTripper, error) {
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
}

// TLSBoundRoundTripper sends requests over connections whose leaf
// certificate carries one attested TLS key.
type TLSBoundRoundTripper struct {
	key       string
	transport *http.Transport
}

var _ http.RoundTripper = &TLSBoundRoundTripper{}

// newTLSBoundRoundTripper pins connections to key, an attested TLS key
// fingerprint, on a transport built from http.DefaultTransport's settings.
func newTLSBoundRoundTripper(key string) (*TLSBoundRoundTripper, error) {
	if key == "" {
		return nil, &errs.ConfigurationError{Err: errNoValidCertificate}
	}
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok || dt == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("TLS transport mode requires http.DefaultTransport to be a non-nil *http.Transport")}
	}
	transport, err := pinnedTransport(dt, key)
	if err != nil {
		return nil, err
	}
	return &TLSBoundRoundTripper{key: key, transport: transport}, nil
}

// pinnedTransport returns a transport whose connections must each present
// key. It starts from an empty transport and copies only the settings of dt
// that choose a route or tune the connection pool, so a setting it doesn't
// copy, including any a later Go release adds, can't skip or weaken the pin.
// Go then makes every TLS handshake itself and checks the pin in
// VerifyConnection, on a direct connection or through a proxy's CONNECT
// tunnel. A TLS dialer or key log is refused rather than dropped, since the
// caller set it expecting it to apply.
func pinnedTransport(dt *http.Transport, key string) (*http.Transport, error) {
	// Clone waits for Go's HTTP/2 setup of dt and leaves out the TLSNextProto
	// entry that setup adds, so base holds only what the caller configured.
	base := dt.Clone()
	if base.DialTLSContext != nil || base.DialTLS != nil {
		return nil, &errs.ConfigurationError{Err: errCustomTLSDialer}
	}

	// GODEBUG settings can lower Go's default minimum version.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	var callerVerifyConnection func(tls.ConnectionState) error
	if c := base.TLSClientConfig; c != nil {
		if c.KeyLogWriter != nil {
			return nil, &errs.ConfigurationError{Err: errKeyLog}
		}
		// Roots decide only the normal certificate check, which runs before
		// the pin, and the callbacks can only reject, so none of them can
		// admit a peer the pin refuses.
		tlsConfig.RootCAs = c.RootCAs
		tlsConfig.VerifyPeerCertificate = c.VerifyPeerCertificate
		callerVerifyConnection = c.VerifyConnection
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if callerVerifyConnection != nil {
			if err := callerVerifyConnection(state); err != nil {
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

	pinned := &http.Transport{
		// The route. Each returns a plain connection, which Go then makes its
		// own TLS handshake over.
		Proxy:                  base.Proxy,
		OnProxyConnectResponse: base.OnProxyConnectResponse,
		ProxyConnectHeader:     base.ProxyConnectHeader,
		GetProxyConnectHeader:  base.GetProxyConnectHeader,
		DialContext:            base.DialContext,
		Dial:                   base.Dial,

		TLSClientConfig: tlsConfig,

		// Connection and pool tuning, which can't change what is verified.
		TLSHandshakeTimeout:    base.TLSHandshakeTimeout,
		DisableKeepAlives:      base.DisableKeepAlives,
		DisableCompression:     base.DisableCompression,
		MaxIdleConns:           base.MaxIdleConns,
		MaxIdleConnsPerHost:    base.MaxIdleConnsPerHost,
		MaxConnsPerHost:        base.MaxConnsPerHost,
		IdleConnTimeout:        base.IdleConnTimeout,
		ResponseHeaderTimeout:  base.ResponseHeaderTimeout,
		ExpectContinueTimeout:  base.ExpectContinueTimeout,
		MaxResponseHeaderBytes: base.MaxResponseHeaderBytes,
		WriteBufferSize:        base.WriteBufferSize,
		ReadBufferSize:         base.ReadBufferSize,
		ForceAttemptHTTP2:      base.ForceAttemptHTTP2,
		HTTP2:                  base.HTTP2,
		Protocols:              base.Protocols,
	}
	// An empty TLSNextProto is the documented way to turn off HTTP/2. Any
	// entry is a protocol the caller installed, which Go's own HTTP/2 replaces.
	if base.TLSNextProto != nil && len(base.TLSNextProto) == 0 {
		pinned.TLSNextProto = base.TLSNextProto
	}
	return pinned, nil
}

func (t *TLSBoundRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	// Transport validates this too, but the round tripper can be used alone.
	if r.URL == nil || r.URL.Scheme != "https" {
		return nil, &errs.ConfigurationError{Err: errNoTLS}
	}

	resp, err := t.transport.RoundTrip(r)
	// A failed certificate check, the pin included, fails the handshake, so
	// no request reached the application.
	if isCertificateError(err) {
		err = &peerLacksKeyError{errs.WrapAttestation(err)}
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
