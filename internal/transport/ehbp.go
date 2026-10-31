package transport

import (
	"errors"
	"fmt"
	"net/http"

	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

var errEHBPTunnel = errors.New("EHBP seals only request and response bodies, so it can't protect a protocol upgrade, such as a WebSocket, or a CONNECT tunnel; use the TLS transport mode on a direct connection")

// WithEHBP returns a Transport that seals request and response bodies to the
// HPKE key e's current verification attests, and sends the sealed requests
// over next; nil next uses http.DefaultTransport, as http.Client does. It
// refuses the requests CheckEHBP rejects.
func WithEHBP(next http.RoundTripper, e *enclave.Enclave) *Transport {
	return &Transport{enclave: e, mode: ehbpMode{next: next}}
}

// ehbpMode seals bodies to the attested HPKE key and sends them over next.
type ehbpMode struct{ next http.RoundTripper }

func (ehbpMode) validateRequest(req *http.Request) error { return CheckEHBP(req) }

func (m ehbpMode) newRoundTripper(v *verify.Verification) (http.RoundTripper, error) {
	key, ok := v.HPKEPublicKey()
	if !ok {
		return nil, &errs.AttestationError{Err: errors.New("document endorses no HPKE key; cannot use the EHBP transport mode (use the TLS transport mode)")}
	}
	identity, err := ehbpidentity.FromPublicKeyHex(key)
	if err != nil {
		return nil, &errs.AttestationError{Err: fmt.Errorf("failed to parse HPKE public key: %w", err)}
	}
	sealing, err := ehbpclient.NewTransportWithIdentity(identity, ehbpclient.WithHTTPClient(&http.Client{Transport: m.next}))
	if err != nil {
		return nil, &errs.AttestationError{Err: fmt.Errorf("failed to create EHBP transport: %w", err)}
	}
	return &ehbpRoundTripper{sealing: sealing}, nil
}

// ehbpRoundTripper seals requests to one attested HPKE key.
type ehbpRoundTripper struct {
	// sealing is an ehbpclient.Transport; the interface lets tests stand in.
	sealing http.RoundTripper
}

func (t *ehbpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.sealing.RoundTrip(req)
	// The enclave answers a body sealed to a key it no longer holds with a
	// key config mismatch, which ehbpclient reports as a KeyConfigError.
	if ehbpidentity.IsKeyConfigError(err) {
		err = &peerLacksKeyError{err}
	}
	return resp, err
}

// CheckEHBP returns a ConfigurationError for a request whose traffic continues
// outside the bodies EHBP seals: a protocol upgrade, such as a WebSocket, or a
// CONNECT tunnel. Sending one would look protected while nothing after the
// handshake is. Other requests are allowed, with or without a body; like every
// EHBP request, their method, URL and headers aren't sealed.
func CheckEHBP(req *http.Request) error {
	if req.Method == http.MethodConnect || req.Header.Get("Upgrade") != "" {
		return &errs.ConfigurationError{Err: errEHBPTunnel}
	}
	return nil
}
