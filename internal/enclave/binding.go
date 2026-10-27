package enclave

import (
	"errors"
	"fmt"
	"net/http"

	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// A Binding ties request traffic to a key that a verification attests.
type Binding interface {
	// Transport builds a transport that reaches only the key v attests. It
	// receives a detached result and must only construct the transport; it
	// must not call the handle's verification, transport setup, or request
	// methods.
	Transport(v *verify.Verification) (http.RoundTripper, error)
	// KeyRejected reports an error meaning the peer does not hold the
	// attested key, detected before the application processes the request.
	KeyRejected(err error) bool
	// Check returns a ConfigurationError for a request the binding can't
	// protect. BoundTransport calls it before verifying, so such a request
	// fails without network I/O.
	Check(req *http.Request) error
}

var (
	// TLS pins each connection's leaf certificate to the attested TLS key.
	TLS Binding = tlsBinding{}
	// EHBP seals request bodies to the attested HPKE key. It refuses protocol
	// upgrades, such as WebSockets, and CONNECT tunnels.
	EHBP Binding = ehbpBinding{}
)

var errEHBPTunnel = errors.New("EHBP seals only request and response bodies, so it can't protect a protocol upgrade, such as a WebSocket, or a CONNECT tunnel; use the TLS binding on a direct connection")

type tlsBinding struct{}

func (tlsBinding) Transport(v *verify.Verification) (http.RoundTripper, error) {
	key, ok := v.TLSPublicKeyFP()
	if !ok {
		return nil, &AttestationError{Err: errNoTLSKey}
	}
	return &TLSBoundRoundTripper{ExpectedPublicKey: key}, nil
}

func (tlsBinding) KeyRejected(err error) bool { return isCertificateError(err) }

// Check refuses a plaintext request, which no pinned connection carries.
func (tlsBinding) Check(req *http.Request) error {
	if req.URL == nil || req.URL.Scheme != "https" {
		return &ConfigurationError{Err: errNoTLS}
	}
	return nil
}

type ehbpBinding struct{}

func (ehbpBinding) Transport(v *verify.Verification) (http.RoundTripper, error) {
	key, ok := v.HPKEPublicKey()
	if !ok {
		return nil, &AttestationError{Err: errors.New("document endorses no HPKE key; cannot use the EHBP binding (use the TLS binding)")}
	}
	identity, err := ehbpidentity.FromPublicKeyHex(key)
	if err != nil {
		return nil, &AttestationError{Err: fmt.Errorf("failed to parse HPKE public key: %w", err)}
	}
	transport, err := ehbpclient.NewTransportWithIdentity(identity)
	if err != nil {
		return nil, &AttestationError{Err: fmt.Errorf("failed to create EHBP transport: %w", err)}
	}
	return transport, nil
}

func (ehbpBinding) KeyRejected(err error) bool { return ehbpidentity.IsKeyConfigError(err) }

// Check refuses a request whose traffic continues outside the bodies EHBP
// seals: a protocol upgrade, such as a WebSocket, or a CONNECT tunnel. Sending
// one would look protected while nothing after the handshake is. Other
// requests are allowed, with or without a body; like every EHBP request, their
// method, URL and headers aren't sealed.
func (ehbpBinding) Check(req *http.Request) error {
	if req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" {
		return &ConfigurationError{Err: errEHBPTunnel}
	}
	return nil
}
