package enclave

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// NewTransport sends each request over the transport b builds for a state h
// ensures is valid. It does no network I/O: the first request or
// EnsureVerified verifies. Key rejection invalidates the state the request was
// sent under and is reported through IsKeyRejection; request replay belongs to
// the caller. Transports from one handle share its verification and refresh.
func NewTransport(h *Handle, b Binding) (*Transport, error) {
	if b == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("transport binding is required")}
	}
	return &Transport{handle: h, binding: b}, nil
}

// Transport binds requests to the keys of a handle's current state. It builds
// its binding's transport once per state, on the first request under it.
type Transport struct {
	handle  *Handle
	binding Binding

	mu    sync.Mutex
	state *State // the state inner was built for
	inner http.RoundTripper
}

// errSuperseded reports a state that a newer one replaced after the request
// was admitted under it.
var errSuperseded = errors.New("verification superseded")

// EnsureVerified returns a state that is valid now, with the binding's
// transport built for it, verifying first only if needed.
func (t *Transport) EnsureVerified(ctx context.Context) (*State, error) {
	_, state, err := t.admit(ctx)
	return state, err
}

func (t *Transport) admit(ctx context.Context) (http.RoundTripper, *State, error) {
	for {
		state, err := t.handle.verifiedState(ctx, false, verificationRetries)
		if err != nil {
			return nil, nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		inner, err := t.innerFor(state)
		if errors.Is(err, errSuperseded) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		t.handle.stateMu.RLock()
		valid := state.valid()
		t.handle.stateMu.RUnlock()
		if valid {
			return inner, state, nil
		}
	}
}

// innerFor returns the binding's transport for state, building it when state
// is newer than the one the current transport was built for.
func (t *Transport) innerFor(state *State) (http.RoundTripper, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case state == t.state:
		return t.inner, nil
	case t.state != nil && state.generation < t.state.generation:
		return nil, errSuperseded
	}
	inner, err := t.binding.Transport(state.Verification())
	if inner == nil && err == nil {
		err = fmt.Errorf("transport binding returned nil")
	}
	if err != nil {
		closeIdleConnections(inner)
		return nil, err
	}
	// Idle connections of the previous transport are bound to its keys.
	closeIdleConnections(t.inner)
	t.state, t.inner = state, inner
	return inner, nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	inner, state, err := t.admit(req.Context())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := inner.RoundTrip(req)
	if err == nil || !t.binding.KeyRejected(err) {
		return resp, err
	}
	t.handle.Invalidate(state)
	return resp, &keyRejectionError{err}
}

func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	inner := t.inner
	t.mu.Unlock()
	closeIdleConnections(inner)
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
