package enclave

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// NewTransport admits requests through h only with unexpired verification and
// sends them over the transport b builds for it. Key rejection invalidates the
// affected state and is reported through IsKeyRejection. Request replay belongs
// to the caller. All transports from one handle share its verification and
// refresh state.
func NewTransport(h *Handle, b Binding) (http.RoundTripper, error) {
	if b == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("transport binding is required")}
	}
	t := &clientTransport{client: h, binding: b}
	if err := h.registerTransport(t); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Handle) registerTransport(t *clientTransport) error {
	for {
		state, err := s.verifiedState(context.Background(), false, verificationRetries)
		if err != nil {
			return err
		}
		s.stateMu.RLock()
		valid := state.valid()
		registered := state.transports[t] != nil
		s.stateMu.RUnlock()
		if !valid {
			continue
		}
		if registered {
			return nil
		}
		transport, err := t.buildTransport(state.Verification)
		if err != nil {
			return err
		}
		s.stateMu.Lock()
		call := s.refreshing
		if s.state == state && call == nil && state.valid() {
			if state.transports == nil {
				state.transports = make(map[*clientTransport]http.RoundTripper)
			}
			if existing := state.transports[t]; existing != nil {
				s.stateMu.Unlock()
				closeIdleConnections(transport)
				return nil
			}
			state.transports[t] = transport
			s.stateMu.Unlock()
			return nil
		}
		s.stateMu.Unlock()
		closeIdleConnections(transport)
		// Register only against the completed refresh, so every later refresh
		// includes this transport in the state it publishes.
		if call != nil {
			<-call.done
		}
	}
}

type clientTransport struct {
	client  *Handle
	binding Binding
}

func (t *clientTransport) buildTransport(verified *verify.Verification) (http.RoundTripper, error) {
	transport, err := t.binding.Transport(detached(verified))
	if transport == nil && err == nil {
		err = fmt.Errorf("transport binding returned nil")
	}
	if err != nil {
		closeIdleConnections(transport)
	}
	return transport, err
}

func (t *clientTransport) admit(ctx context.Context) (http.RoundTripper, *enclaveState, error) {
	for {
		state, err := t.client.verifiedState(ctx, false, verificationRetries)
		if err != nil {
			return nil, nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		t.client.stateMu.RLock()
		transport := state.transports[t]
		valid := state.valid()
		t.client.stateMu.RUnlock()
		if valid {
			return transport, state, nil
		}
	}
}

func (t *clientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport, state, err := t.admit(req.Context())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := transport.RoundTrip(req)
	if err == nil || !t.binding.KeyRejected(err) {
		return resp, err
	}
	t.client.invalidate(state)
	return resp, &keyRejectionError{err}
}

func (t *clientTransport) CloseIdleConnections() {
	t.client.stateMu.RLock()
	transport := t.client.state.transports[t]
	t.client.stateMu.RUnlock()
	closeIdleConnections(transport)
}

func closeIdleConnections(transport http.RoundTripper) {
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

// IsKeyRejection reports a binding rejection before application processing.
// The affected state has already been invalidated. A caller may recover and
// replay once if its request body is replayable; the original cause is preserved.
func IsKeyRejection(err error) bool {
	var rejection interface{ KeyRejected() bool }
	return errors.As(err, &rejection) && rejection.KeyRejected()
}

type keyRejectionError struct{ error }

func (e *keyRejectionError) Unwrap() error     { return e.error }
func (e *keyRejectionError) KeyRejected() bool { return true }

func isCertificateError(err error) bool {
	var certInvalidErr x509.CertificateInvalidError
	var unknownAuthErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certVerifyErr *tls.CertificateVerificationError
	return errors.Is(err, errCertMismatch) ||
		errors.As(err, &certInvalidErr) || errors.As(err, &unknownAuthErr) ||
		errors.As(err, &hostnameErr) || errors.As(err, &certVerifyErr)
}
