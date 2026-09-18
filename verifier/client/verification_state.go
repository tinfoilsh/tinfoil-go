package client

import (
	"context"
	"errors"
	"time"
)

const verificationTimeout = 30 * time.Second

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
	ctx   context.Context
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
		refreshCtx, cancel := context.WithTimeout(context.Background(), verificationTimeout)
		call = &verificationCall{ctx: refreshCtx, done: make(chan struct{})}
		s.refreshing = call
		go s.refresh(call, cancel)
	}
	s.stateMu.Unlock()

	// A caller's cancellation does not abort a refresh needed by other callers.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
	case <-call.ctx.Done():
		select {
		case <-call.done:
		default:
			return nil, call.ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return call.state, call.err
}

func (s *SecureClient) refresh(call *verificationCall, cancel context.CancelFunc) {
	defer cancel()
	verify := s.verify
	if verify == nil {
		verify = s.fetchVerification
	}
	state, err := verify(call.ctx)
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if call.ctx.Err() != nil {
		err = call.ctx.Err()
	}
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
