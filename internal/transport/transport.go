// Package transport holds the http.RoundTrippers the routes stack in front of
// an enclave, one kind per file. Transport, built by TLS or WithEHBP, ties
// requests to the keys of a handle's current verification; the With functions
// each layer one more round tripper onto another, and each route chooses which
// to stack, in what order.
package transport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Transport sends each request over a transport tied to the keys of its
// handle's current verification, which TLS or WithEHBP builds once per
// verification, on the first request under it. It does no network I/O until
// then: the first request or EnsureVerified verifies. A key rejection
// invalidates the verification the request was sent under and is reported
// through IsKeyRejection; replaying the request is up to the caller.
// Transports on one handle share its verification and refresh.
type Transport struct {
	handle *enclave.Handle
	// build makes the transport tied to one verification's keys.
	build func(*verify.Verification) (http.RoundTripper, error)
	// keyRejected reports an error meaning the peer doesn't hold the attested
	// key, detected before the application processes the request.
	keyRejected func(error) bool
	// check returns a ConfigurationError for a request the keys can't protect,
	// before any network I/O.
	check func(*http.Request) error

	mu    sync.Mutex
	state *enclave.State // the state inner was built for
	inner http.RoundTripper
}

// errSuperseded reports a state that a newer one replaced after the request
// was admitted under it.
var errSuperseded = errors.New("verification superseded")

// EnsureVerified returns a state that is valid now, with the transport built
// for it, verifying first only if needed.
func (t *Transport) EnsureVerified(ctx context.Context) (*enclave.State, error) {
	_, state, err := t.admit(ctx)
	return state, err
}

func (t *Transport) admit(ctx context.Context) (http.RoundTripper, *enclave.State, error) {
	for {
		state, err := t.handle.EnsureVerified(ctx)
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
		if t.handle.Valid(state) {
			return inner, state, nil
		}
	}
}

// innerFor returns the transport for state, building it when state is newer
// than the one the current transport was built for.
func (t *Transport) innerFor(state *enclave.State) (http.RoundTripper, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case state == t.state:
		return t.inner, nil
	case t.state != nil && state.Generation() < t.state.Generation():
		return nil, errSuperseded
	}
	// Idle connections of the current transport are bound to keys a newer
	// state replaced, whether or not its transport builds.
	closeIdleConnections(t.inner)
	inner, err := t.build(state.Verification())
	if inner == nil && err == nil {
		err = fmt.Errorf("transport build returned nil")
	}
	if err != nil {
		closeIdleConnections(inner)
		return nil, err
	}
	t.state, t.inner = state, inner
	return inner, nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.check(req); err != nil {
		closeRequestBody(req)
		return nil, err
	}
	inner, state, err := t.admit(req.Context())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := inner.RoundTrip(req)
	if err == nil || !t.keyRejected(err) {
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

// IsKeyRejection reports a key rejection before application processing. The
// affected state has already been invalidated. A caller may recover and replay
// once if its request body is replayable; the original cause is preserved.
func IsKeyRejection(err error) bool {
	var rejection interface{ KeyRejected() bool }
	return errors.As(err, &rejection) && rejection.KeyRejected()
}

type keyRejectionError struct{ error }

func (e *keyRejectionError) Unwrap() error     { return e.error }
func (e *keyRejectionError) KeyRejected() bool { return true }

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
