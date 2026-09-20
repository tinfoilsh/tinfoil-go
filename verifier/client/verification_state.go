package client

import (
	"context"
	"errors"
	"time"
)

// ErrFreshnessExpired means the authenticated witnesses no longer authorize requests.
var ErrFreshnessExpired = errors.New("attestation freshness witnesses have expired")

type verificationCall struct {
	done  chan struct{}
	state *VerifiedDocumentV3
	err   error
}

// verifiedState shares one refresh (including its failure) across all waiters.
// A key-rotation retry can reuse a newer snapshot installed by another caller.
func (s *SecureClient) verifiedState(ctx context.Context, observed *VerifiedDocumentV3, force bool) (*VerifiedDocumentV3, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.stateMu.Lock()
	state := s.state
	if state != nil && time.Now().Before(state.FreshnessExpiresAt) && (!force || observed != nil && state != observed) {
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
	state, err := verify()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err == nil && !time.Now().Before(state.FreshnessExpiresAt) {
		err = ErrFreshnessExpired
	}
	if err == nil {
		s.state = state
		call.state = state
	}
	call.err = err
	s.refreshing = nil
	close(call.done)
}
