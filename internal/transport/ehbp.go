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

var errEHBPTunnel = errors.New("EHBP seals only request and response bodies, so it can't protect a protocol upgrade, such as a WebSocket, or a CONNECT tunnel; use the TLS binding on a direct connection")

// WithEHBP returns a Transport that seals request and response bodies to the
// HPKE key h's current verification attests, and sends the sealed requests
// over next; nil next uses http.DefaultTransport, as http.Client does. It
// refuses the requests CheckEHBP rejects.
func WithEHBP(next http.RoundTripper, h *enclave.Handle) *Transport {
	return &Transport{
		handle: h,
		build: func(v *verify.Verification) (http.RoundTripper, error) {
			key, ok := v.HPKEPublicKey()
			if !ok {
				return nil, &errs.AttestationError{Err: errors.New("document endorses no HPKE key; cannot use the EHBP binding (use the TLS binding)")}
			}
			identity, err := ehbpidentity.FromPublicKeyHex(key)
			if err != nil {
				return nil, &errs.AttestationError{Err: fmt.Errorf("failed to parse HPKE public key: %w", err)}
			}
			sealing, err := ehbpclient.NewTransportWithIdentity(identity, ehbpclient.WithHTTPClient(&http.Client{Transport: next}))
			if err != nil {
				return nil, &errs.AttestationError{Err: fmt.Errorf("failed to create EHBP transport: %w", err)}
			}
			return sealing, nil
		},
		keyRejected: ehbpidentity.IsKeyConfigError,
		check:       CheckEHBP,
	}
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
