package enclave

import (
	"context"
	"errors"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// ErrFreshnessExpired means the authenticated witnesses no longer authorize
// requests.
var ErrFreshnessExpired = errors.New("attestation freshness witnesses have expired; retry verification with fresh evidence")

const (
	verificationRetries          = 1
	candidateVerificationRetries = 0
	verificationRetryDelay       = time.Second
)

// State is one successful verification. Transports build per State, and
// Invalidate targets a State.
type State struct {
	verification *verify.Verification
	// generation orders the states a handle publishes.
	generation uint64
	// rejected is guarded by the handle's stateMu.
	rejected bool
}

// Verification returns a copy of the verification for the caller to keep.
func (state *State) Verification() *verify.Verification {
	return detached(state.verification)
}

// Generation orders the states a handle publishes: a later state has a higher
// generation.
func (state *State) Generation() uint64 {
	return state.generation
}

type verificationCall struct {
	done  chan struct{}
	state *State
	err   error
}

// verifiedState shares one refresh (including its failure) across all waiters.
func (s *Handle) verifiedState(ctx context.Context, force bool, retries int) (*State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.stateMu.Lock()
	state := s.state
	if state != nil && state.valid() && !force {
		s.stateMu.Unlock()
		return state, nil
	}
	call := s.refreshing
	if call == nil {
		call = &verificationCall{done: make(chan struct{})}
		s.refreshing = call
		go s.refresh(call, retries)
	}
	s.stateMu.Unlock()

	// A caller's cancellation does not abort a refresh needed by other callers.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return call.state, call.err
}

func (s *Handle) refresh(call *verificationCall, retries int) {
	fetch := s.verify
	if fetch == nil {
		fetch = s.fetchVerification
	}
	// The attestation fetch bounds its network I/O. Local verification has no
	// SDK deadline; each caller can independently cancel its wait above.
	var verified *verify.Verification
	var err, firstErr error
	for attempt := 0; ; attempt++ {
		verified, err = fetch()
		if err == nil && !time.Now().Before(verified.FreshnessExpiresAt()) {
			err = &AttestationError{Err: ErrFreshnessExpired}
		}
		if attempt == retries || !retryableVerification(err) {
			break
		}
		firstErr = err
		time.Sleep(verificationRetryDelay)
	}
	s.stateMu.Lock()
	if err == nil && !time.Now().Before(verified.FreshnessExpiresAt()) {
		err = &AttestationError{Err: ErrFreshnessExpired}
	}
	if err != nil && firstErr != nil {
		err = errors.Join(err, firstErr)
	}
	if err == nil {
		s.generation++
		s.state = &State{verification: verified, generation: s.generation}
		call.state = s.state
	}
	call.err = err
	s.refreshing = nil
	close(call.done)
	s.stateMu.Unlock()
}

// valid is called with the handle's stateMu held.
func (state *State) valid() bool {
	return !state.rejected && time.Now().Before(state.verification.FreshnessExpiresAt())
}

// Valid reports whether state can still authorize requests: it hasn't expired
// or been invalidated.
func (s *Handle) Valid(state *State) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return state.valid()
}

// Invalidate marks state rejected, so the next EnsureVerified verifies again.
// Invalidating a superseded state leaves the current one valid.
func (s *Handle) Invalidate(state *State) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	state.rejected = true
}

func retryableVerification(err error) bool {
	var config *ConfigurationError
	if errors.As(err, &config) {
		return false
	}
	// Joined failures put the terminal cause first; earlier probes are diagnostics.
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		causes := joined.Unwrap()
		return len(causes) > 0 && retryableVerification(causes[0])
	}
	var fetch *NetworkError
	var attestation *AttestationError
	return errors.As(err, &fetch) || errors.As(err, &attestation)
}
