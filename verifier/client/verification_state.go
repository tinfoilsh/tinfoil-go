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

type enclaveEntry struct {
	state      *enclaveState
	refreshing *verificationCall
}

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
func (s *SecureClient) verifiedState(ctx context.Context, enclave string, force bool, retries int, adapter *refreshingTransport) (*enclaveState, error) {
	if s == nil {
		return nil, &ConfigurationError{Err: errors.New("secure client is required")}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.stateMu.Lock()
	entry := s.entry(enclave)
	state := entry.state
	if state != nil && state.valid() && !force {
		s.stateMu.Unlock()
		return state, nil
	}
	call := entry.refreshing
	if call == nil {
		call = &verificationCall{done: make(chan struct{})}
		entry.refreshing = call
		go s.refresh(enclave, entry, call, retries, adapter)
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

func (s *SecureClient) refresh(enclave string, entry *enclaveEntry, call *verificationCall, retries int, adapter *refreshingTransport) {
	s.stateMu.RLock()
	previous := entry.state
	s.stateMu.RUnlock()
	// The attestation fetch bounds its network I/O. Local verification has no
	// SDK deadline; each caller can independently cancel its wait above.
	var verified *VerifiedDocumentV3
	var err, firstErr error
	for attempt := 0; ; attempt++ {
		verified, err = s.fetchEnclaveVerification(enclave)
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
	if err == nil {
		verified.EnclaveHost = enclave
	}
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
	if err == nil && adapter != nil && state.transports[adapter] == nil {
		state.transports[adapter], err = adapter.buildTransport(verified)
	}
	s.stateMu.Lock()
	if err == nil && !time.Now().Before(state.FreshnessExpiresAt) {
		err = &AttestationError{Err: errFreshnessExpired}
	}
	if err != nil && firstErr != nil {
		err = errors.Join(err, firstErr)
	}
	if err == nil {
		entry.state = state
		call.state = state
	}
	call.err = err
	entry.refreshing = nil
	if err != nil && entry.state == nil {
		delete(s.enclaves, enclave)
	}
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

// entry is called with stateMu held.
func (s *SecureClient) entry(enclave string) *enclaveEntry {
	if s.enclaves == nil {
		s.enclaves = make(map[string]*enclaveEntry)
	}
	entry := s.enclaves[enclave]
	if entry == nil {
		entry = &enclaveEntry{}
		s.enclaves[enclave] = entry
	}
	return entry
}
