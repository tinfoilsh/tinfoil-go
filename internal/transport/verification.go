package transport

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// state is one successful verification and the round tripper created for its
// keys. They are published together, so a request never sends under keys
// other than those of the verification it checked.
type state struct {
	verification *verify.Verification
	roundTripper http.RoundTripper
	// rejected is guarded by the Transport's mu.
	rejected bool
}

// valid is called with the Transport's mu held.
func (s *state) valid() bool {
	return !s.rejected && time.Now().Before(s.verification.FreshnessExpiresAt())
}

// EnsureVerified returns a verification that is valid now, verifying first
// only if the current one has expired or been invalidated. A nil error means
// requests can be sent under it.
func (t *Transport) EnsureVerified(ctx context.Context) (*verify.Verification, error) {
	s, err := t.verified(ctx, false, (*enclave.Enclave).Verify)
	if err != nil {
		return nil, err
	}
	return enclave.Detached(s.verification), nil
}

// Reverify verifies again even if the current verification is still valid.
func (t *Transport) Reverify(ctx context.Context) (*verify.Verification, error) {
	s, err := t.verified(ctx, true, (*enclave.Enclave).Verify)
	if err != nil {
		return nil, err
	}
	return enclave.Detached(s.verification), nil
}

// VerifyOnce verifies like Reverify but doesn't retry a failed attempt, so a
// caller trying several enclaves moves on quickly.
func (t *Transport) VerifyOnce(ctx context.Context) (*verify.Verification, error) {
	s, err := t.verified(ctx, true, (*enclave.Enclave).VerifyOnce)
	if err != nil {
		return nil, err
	}
	return enclave.Detached(s.verification), nil
}

// Current returns the last successful verification without checking it, or
// nil before the first. It may have expired or been invalidated; use
// EnsureVerified for one that is valid.
func (t *Transport) Current() *verify.Verification {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.current == nil {
		return nil
	}
	return enclave.Detached(t.current.verification)
}

// verified returns a valid state, refreshing it first when force is set or
// the current one is invalid. Concurrent callers share one refresh, including
// its failure.
func (t *Transport) verified(ctx context.Context, force bool, verify func(*enclave.Enclave) (*verify.Verification, error)) (*state, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		t.mu.Lock()
		if s := t.current; s != nil && s.valid() && !force {
			t.mu.Unlock()
			return s, nil
		}
		// DoChan runs the refresh in its own goroutine, which takes mu only
		// after this caller releases it.
		refreshed := t.refreshes.DoChan("", func() (any, error) { return nil, t.refresh(verify) })
		t.mu.Unlock()

		// A caller's cancellation does not abort a refresh other callers need.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-refreshed:
			if result.Err != nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return nil, result.Err
			}
		}
		// A request can reject the new state before this caller wakes, so
		// check t.current again rather than trust the refresh's result.
		force = false
	}
}

// refresh verifies the enclave and publishes the result as the current state.
func (t *Transport) refresh(verify func(*enclave.Enclave) (*verify.Verification, error)) error {
	// The attestation fetch bounds its network I/O. Local verification has no
	// SDK deadline; each caller can independently cancel its wait above.
	verified, err := verify(t.enclave)
	var s *state
	if err == nil {
		s, err = t.newState(verified)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// Creating the round tripper or waiting for mu can outlast freshness.
	if err == nil && !s.valid() {
		closeIdleConnections(s.roundTripper)
		err = &enclave.AttestationError{Err: enclave.ErrFreshnessExpired}
	}
	if err == nil {
		// Idle connections of the replaced state are tied to its keys.
		if t.current != nil {
			closeIdleConnections(t.current.roundTripper)
		}
		t.current = s
	}
	return err
}

// newState creates the mode's round tripper for v.
func (t *Transport) newState(v *verify.Verification) (*state, error) {
	// The mode gets a copy, so it can't change the verification kept here.
	rt, err := t.mode.newRoundTripper(enclave.Detached(v))
	if rt == nil && err == nil {
		err = fmt.Errorf("transport mode returned a nil round tripper")
	}
	if err != nil {
		closeIdleConnections(rt)
		return nil, err
	}
	return &state{verification: v, roundTripper: rt}, nil
}

// invalidate marks s rejected, so the next request verifies again.
// Invalidating a replaced state leaves the current one valid.
func (t *Transport) invalidate(s *state) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s.rejected = true
}
