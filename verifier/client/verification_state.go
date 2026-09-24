package client

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// errFreshnessExpired means the authenticated witnesses no longer authorize requests.
var errFreshnessExpired = errors.New("attestation freshness witnesses have expired; retry verification with fresh evidence")

type enclaveState struct {
	*VerifiedDocumentV3
	transports map[*clientTransport]http.RoundTripper
}

type verificationCall struct {
	done  chan struct{}
	state *enclaveState
	err   error
}

// verifiedState shares one refresh (including its failure) across all waiters.
// A key-rotation retry can reuse a newer snapshot installed by another caller.
func (s *SecureClient) verifiedState(ctx context.Context, observed *enclaveState, force bool) (*enclaveState, error) {
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
	s.stateMu.RLock()
	previous := s.state
	s.stateMu.RUnlock()
	verify := s.verify
	if verify == nil {
		verify = s.fetchVerification
	}
	// The attestation fetch bounds its network I/O. Local verification has no
	// SDK deadline; each caller can independently cancel its wait above.
	verified, err := verify()
	if err == nil && !time.Now().Before(verified.FreshnessExpiresAt) {
		err = &AttestationError{Err: errFreshnessExpired}
	}
	state := &enclaveState{VerifiedDocumentV3: verified, transports: make(map[*clientTransport]http.RoundTripper)}
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
