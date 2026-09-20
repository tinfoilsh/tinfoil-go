package client

import (
	"context"
	"errors"
	"time"
)

// ErrFreshnessExpired means the authenticated witnesses no longer authorize requests.
var ErrFreshnessExpired = errors.New("attestation freshness witnesses have expired")

// Published snapshots are immutable. Keys, their deadline and the displayed
// verification result always come from the same verification attempt.
type verificationState struct {
	verified    *VerifiedDocumentV3
	groundTruth *GroundTruth
	document    *VerificationDocument
	generation  uint64
}

type verificationCall struct {
	done  chan struct{}
	state *verificationState
	err   error
}

// verifiedState shares one refresh (including its failure) across all waiters.
// A key-rotation retry can reuse a newer generation installed by another caller.
func (s *SecureClient) verifiedState(ctx context.Context, observed *verificationState, force bool) (*verificationState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.stateMu.Lock()
	state := s.state
	if state != nil && time.Now().Before(state.verified.FreshnessExpiresAt) && (!force || observed != nil && state.generation != observed.generation) {
		s.stateMu.Unlock()
		return state, nil
	}
	call := s.refreshing
	if call == nil {
		call = &verificationCall{done: make(chan struct{})}
		s.refreshing = call
		go s.refresh(call)
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

func (s *SecureClient) refresh(call *verificationCall) {
	verify := s.verify
	if verify == nil {
		verify = s.fetchVerification
	}
	// The attestation fetch bounds its network I/O. Local verification has no
	// SDK deadline; each caller can independently cancel its wait above.
	state, err := verify(context.Background())
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err == nil && !time.Now().Before(state.verified.FreshnessExpiresAt) {
		err = ErrFreshnessExpired
	}
	if err == nil {
		state.generation = 1
		if s.state != nil {
			state.generation = s.state.generation + 1
		}
		s.state = state
		call.state = state
	}
	call.err = err
	s.refreshing = nil
	close(call.done)
}
