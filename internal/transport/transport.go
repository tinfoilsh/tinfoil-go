// Package transport holds the http.RoundTrippers the routes stack in front of
// an enclave, one kind per file. Transport, built by TLS or WithEHBP, verifies
// an enclave and ties requests to the keys of its current verification; the
// With functions each layer one more round tripper onto another, and each
// route chooses which to stack, in what order.
package transport

import (
	"errors"
	"net/http"
	"sync"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/sync/singleflight"
)

// Transport verifies its enclave on first use, and again when the verification
// expires or is rejected, and sends each request over a round tripper tied to
// the keys of the current verification. It does no network I/O until then:
// the first request or EnsureVerified verifies, and concurrent callers share
// one verification. A key rejection invalidates the verification the request
// was sent under and is reported through IsKeyRejection; replaying the
// request is up to the caller.
type Transport struct {
	enclave *enclave.Enclave
	mode    mode
	// refreshes runs one refresh at a time for every caller that needs it.
	refreshes singleflight.Group

	// mu is held from a caller's check through its DoChan, so a refresh that
	// finishes after the check can't be followed by a redundant one.
	mu      sync.RWMutex
	current *state
}

// A mode protects requests with the keys of one verification: TLS pins
// connections to its TLS key, and EHBP seals bodies to its HPKE key.
type mode interface {
	// validateRequest returns a ConfigurationError for a request the mode
	// can't protect, before any network I/O.
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

// Enclave returns the enclave the transport verifies.
func (t *Transport) Enclave() *enclave.Enclave {
	return t.enclave
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Validate first, so a request the mode can't protect never triggers a
	// verification.
	if err := t.mode.validateRequest(req); err != nil {
		closeRequestBody(req)
		return nil, err
	}
	s, err := t.verified(req.Context(), false, (*enclave.Enclave).Verify)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := s.roundTripper.RoundTrip(req)
	var lacksKey *peerLacksKeyError
	if !errors.As(err, &lacksKey) {
		return resp, err
	}
	// Invalidate the state the request was sent under, not the current one,
	// so a late rejection can't retire a newer verification.
	t.invalidate(s)
	return resp, &keyRejectionError{err}
}

func (t *Transport) CloseIdleConnections() {
	t.mu.RLock()
	s := t.current
	t.mu.RUnlock()
	if s != nil {
		closeIdleConnections(s.roundTripper)
	}
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
