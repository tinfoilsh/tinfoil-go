package client

import (
	"context"
	"errors"
	"time"
)

// errFreshnessExpired means the authenticated witnesses no longer authorize requests.
var errFreshnessExpired = errors.New("attestation freshness witnesses have expired; retry verification with fresh evidence")

const (
	verificationRetries    = 1
	verificationRetryDelay = time.Second
)

type verificationCall struct {
	done  chan struct{}
	state *VerifiedDocumentV3
	err   error
}

// verifiedState shares one refresh (including its failure) across all waiters.
// A key-rotation retry can reuse a newer snapshot installed by another caller.
func (s *SecureClient) verifiedState(ctx context.Context, observed *VerifiedDocumentV3, force bool) (*VerifiedDocumentV3, error) {
	if s == nil {
		return nil, &ConfigurationError{Err: errors.New("secure client is required")}
	}
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
	var state *VerifiedDocumentV3
	var err, firstErr error
	for attempt := 0; ; attempt++ {
		state, err = verify()
		if err == nil && !time.Now().Before(state.FreshnessExpiresAt) {
			err = &AttestationError{Err: errFreshnessExpired}
		}
		if attempt == verificationRetries || !retryableVerification(err) {
			break
		}
		firstErr = err
		// Nothing from the failed attempt was published. Fetch a fresh nonce and
		// full document after one delay; concurrent callers share this retry.
		time.Sleep(verificationRetryDelay)
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	// Lock contention may have crossed the deadline since the attempt finished.
	if err == nil && !time.Now().Before(state.FreshnessExpiresAt) {
		err = &AttestationError{Err: errFreshnessExpired}
	}
	if err != nil && firstErr != nil {
		err = errors.Join(err, firstErr)
	}
	if err == nil {
		s.state = state
		call.state = state
	}
	call.err = err
	s.refreshing = nil
	close(call.done)
}

// Discard only the rejected snapshot; another caller may already have recovered.
func (s *SecureClient) invalidate(state *VerifiedDocumentV3) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.state == state {
		s.state = nil
	}
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
	var fetch *FetchError
	var attestation *AttestationError
	return errors.As(err, &fetch) || errors.As(err, &attestation)
}
