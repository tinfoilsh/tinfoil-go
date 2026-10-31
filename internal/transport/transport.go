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

// Transport sends each request over a round tripper tied to the keys of its
// handle's current verification, which its mode creates once per
// verification, on the first request under it. It does no network I/O until
// then: the first request or EnsureVerified verifies. A key rejection
// invalidates the verification the request was sent under and is reported
// through IsKeyRejection; replaying the request is up to the caller.
// Transports on one handle share its verification and refresh.
type Transport struct {
	handle *enclave.Handle
	mode   mode

	mu                sync.Mutex
	roundTripperState *enclave.State // the state roundTripper was built from
	roundTripper      http.RoundTripper
}

// A mode protects requests with the keys of one verification: TLS pins
// connections to its TLS key, and EHBP seals bodies to its HPKE key.
type mode interface {
	// validateRequest checks if the mode is able to protect the request and
	// returns a ConfigurationError if not. It does not perform nay network
	// I/O. Some modes may not be able to protect all requests (e.g. EHBP
	// cannot protect requests with no body)
	validateRequest(*http.Request) error
	// newRoundTripper returns a round tripper tied to v's keys. It marks an
	// error meaning the peer doesn't hold those keys, detected before the
	// application processes the request, with peerLacksKeyError.
	newRoundTripper(v *verify.Verification) (http.RoundTripper, error)
}

// peerLacksKeyError is a mode's round tripper reporting that the peer doesn't
// hold the keys it was created for. Transport turns it into a
// keyRejectionError once it has invalidated the state. It is a separate type
// because IsKeyRejection promises that invalidation, which a mode's round
// tripper used alone can't make, so its errors mustn't make a caller replay.
type peerLacksKeyError struct{ error }

func (e *peerLacksKeyError) Unwrap() error { return e.error }

// errSuperseded reports a state that a newer one replaced after the request
// was admitted under it.
var errSuperseded = errors.New("verification superseded")

// EnsureVerified returns a state that is valid now, with the round tripper
// created for it, verifying first only if needed.
func (t *Transport) EnsureVerified(ctx context.Context) (*enclave.State, error) {
	_, state, err := t.admit(ctx)
	return state, err
}

// admit returns a valid state and the round tripper for it. It loops because
// the state can be replaced or invalidated by concurrent requests while the
// round tripper is being created.
func (t *Transport) admit(ctx context.Context) (http.RoundTripper, *enclave.State, error) {
	for {
		// Get the latest verification state from the enclave handle,
		// reverifying if necessary
		state, err := t.handle.EnsureVerified(ctx)
		if err != nil {
			return nil, nil, err
		}
		// A shared verification can succeed after this caller's context ended.
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		// Create a new roundTripper from the latest enclave verification state
		// if that state has changed 
		rt, err := t.roundTripperFor(state)
		if errors.Is(err, errSuperseded) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		// Creating the round tripper can be slow, and state may have expired
		// or been rejected meanwhile; never send under it then.
		if t.handle.Valid(state) {
			return rt, state, nil
		}
	}
}

// roundTripperFor returns the round tripper for state's keys, creating a new
// one when state is newer than roundTripperState.
func (t *Transport) roundTripperFor(state *enclave.State) (http.RoundTripper, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// States are compared by identity: each verification publishes a new
	// State, so a new round tripper is created even if the keys didn't change.
	switch {
	case state == t.roundTripperState:
		return t.roundTripper, nil
	case t.roundTripperState != nil && state.Generation() < t.roundTripperState.Generation():
		// Another request already moved this Transport to a newer state.
		return nil, errSuperseded
	}
	// Idle connections of the current round tripper are tied to keys a newer
	// state replaced, whether or not a new one can be created.
	closeIdleConnections(t.roundTripper)
	rt, err := t.mode.newRoundTripper(state.Verification())
	if rt == nil && err == nil {
		err = fmt.Errorf("transport mode returned a nil round tripper")
	}
	if err != nil {
		closeIdleConnections(rt)
		return nil, err
	}
	t.roundTripperState, t.roundTripper = state, rt
	return rt, nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Validate first, so a request the mode can't protect never triggers a
	// verification.
	if err := t.mode.validateRequest(req); err != nil {
		closeRequestBody(req)
		return nil, err
	}
	rt, state, err := t.admit(req.Context())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := rt.RoundTrip(req)
	var lacksKey *peerLacksKeyError
	if !errors.As(err, &lacksKey) {
		return resp, err
	}
	// Invalidate the state the request was admitted under, not the handle's
	// current one, so a late rejection can't retire a newer verification.
	t.handle.Invalidate(state)
	return resp, &keyRejectionError{err}
}

func (t *Transport) CloseIdleConnections() {
	t.mu.Lock()
	rt := t.roundTripper
	t.mu.Unlock()
	closeIdleConnections(rt)
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
