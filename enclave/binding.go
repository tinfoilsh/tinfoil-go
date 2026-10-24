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
}

var (
	// TLS pins each connection's leaf certificate to the attested TLS key.
	TLS Binding = tlsBinding{}
	// EHBP seals request bodies to the attested HPKE key.
	EHBP Binding = ehbpBinding{}
)

type tlsBinding struct{}

func (tlsBinding) Transport(v *verify.Verification) (http.RoundTripper, error) {
	key, ok := v.TLSPublicKeyFP()
	if !ok {
		return nil, &AttestationError{Err: errNoTLSKey}
	}
	return &TLSBoundRoundTripper{ExpectedPublicKey: key}, nil
}

func (tlsBinding) KeyRejected(err error) bool { return isCertificateError(err) }

type ehbpBinding struct{}

func (ehbpBinding) Transport(v *verify.Verification) (http.RoundTripper, error) {
	key, ok := v.HPKEPublicKey()
	if !ok {
		return nil, &AttestationError{Err: errors.New("document endorses no HPKE key; cannot use the EHBP transport (use WithTransport(TransportTLS))")}
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
