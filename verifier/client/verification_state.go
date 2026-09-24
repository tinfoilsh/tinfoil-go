package client

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// errFreshnessExpired means the authenticated witnesses no longer authorize requests.
var errFreshnessExpired = errors.New("attestation freshness witnesses have expired; retry verification with fresh evidence")

const (
	verificationRetries          = 1
	candidateVerificationRetries = 0
	verificationRetryDelay       = time.Second
)

type enclaveState struct {
	*VerifiedDocumentV3
	rejected   bool
	transports map[*refreshingTransport]http.RoundTripper
}

type verificationCall struct {
	done  chan struct{}
	state *enclaveState
	err   error
}

// verifiedState shares one refresh (including its failure) across all waiters.
// A key-rotation retry can reuse a newer snapshot installed by another caller.
func (s *SecureClient) verifiedState(ctx context.Context, observed *enclaveState, force bool, retries int) (*enclaveState, error) {
	if s == nil {
		return nil, &ConfigurationError{Err: errors.New("secure client is required")}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.stateMu.Lock()
	state := s.state
	if state != nil && state.valid() && (!force || observed != nil && state != observed) {
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

func (s *SecureClient) refresh(call *verificationCall, retries int) {
	s.stateMu.RLock()
	previous := s.state
	s.stateMu.RUnlock()
	verify := s.verify
	if verify == nil {
		verify = s.fetchVerification
	}
	// The attestation fetch bounds its network I/O. Local verification has no
	// SDK deadline; each caller can independently cancel its wait above.
	var verified *VerifiedDocumentV3
	var err, firstErr error
	for attempt := 0; ; attempt++ {
		verified, err = verify()
		if err == nil && !time.Now().Before(verified.FreshnessExpiresAt) {
			err = &AttestationError{Err: errFreshnessExpired}
		}
		if attempt == retries || !retryableVerification(err) {
			break
		}
		firstErr = err
		time.Sleep(verificationRetryDelay)
	}
	state := &enclaveState{VerifiedDocumentV3: verified, transports: make(map[*refreshingTransport]http.RoundTripper)}
	if err == nil && previous != nil {
		for adapter := range previous.transports {
			transport, buildErr := adapter.buildTransport(verified)
			if buildErr != nil {
				err = buildErr
				break
			}
			state.transports[adapter] = transport
		}
	}
	s.stateMu.Lock()
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
	s.stateMu.Unlock()
	if err != nil {
		state.closeIdleConnections()
	} else if previous != nil {
		previous.closeIdleConnections()
	}
}

func (state *enclaveState) closeIdleConnections() {
	for _, transport := range state.transports {
		closeIdleConnections(transport)
	}
}

func (state *enclaveState) valid() bool {
	return !state.rejected && time.Now().Before(state.FreshnessExpiresAt)
}

func (s *SecureClient) invalidate(state *enclaveState) {
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
	var fetch *FetchError
	var attestation *AttestationError
	return errors.As(err, &fetch) || errors.As(err, &attestation)
}
