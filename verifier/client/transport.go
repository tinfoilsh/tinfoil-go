package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
)

// NewTransport admits requests only with unexpired verification. build must
// bind its transport to the supplied attested keys. isKeyError identifies a
// rejection before application processing; nil disables key-rejection detection.
// Rejection invalidates the affected state and is reported through IsKeyRejection.
// Request replay belongs to the caller.
// All transports from this client share its verification and refresh state.
// build receives a detached result and must only construct its bound transport;
// it must not call the client's verification, transport setup, or request methods.
func (s *SecureClient) NewTransport(build func(*VerifiedDocumentV3) (http.RoundTripper, error), isKeyError func(error) bool) (http.RoundTripper, error) {
	if build == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("transport builder is required")}
	}
	t := &clientTransport{client: s, build: build, isKeyError: isKeyError}
	if err := s.registerTransport(t); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *SecureClient) registerTransport(t *clientTransport) error {
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
		transport, err := t.buildTransport(state.VerifiedDocumentV3)
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
	client     *SecureClient
	build      func(*VerifiedDocumentV3) (http.RoundTripper, error)
	isKeyError func(error) bool
}

func (t *clientTransport) buildTransport(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
	transport, err := t.build(cloneVerification(verified))
	if transport == nil && err == nil {
		err = fmt.Errorf("transport builder returned nil")
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
	if err == nil || t.isKeyError == nil || !t.isKeyError(err) {
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
