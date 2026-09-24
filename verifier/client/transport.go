package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
)

// NewTransport admits requests only with unexpired verification. build must
// bind its transport to the supplied attested keys. isKeyError identifies an
// error safe to retry after re-verification; nil disables key-rotation retries.
// All transports from this client share its verification and refresh state.
// build receives a detached result and must only construct its bound transport;
// it must not call the client's verification, transport setup, or request methods.
func (s *SecureClient) NewTransport(build func(*VerifiedDocumentV3) (http.RoundTripper, error), isKeyError func(error) bool) (http.RoundTripper, error) {
	if s == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("secure client is required")}
	}
	if build == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("transport builder is required")}
	}
	t := &refreshingTransport{client: s, build: build, isKeyError: isKeyError}
	if err := s.registerTransport(t); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *SecureClient) registerTransport(t *refreshingTransport) error {
	_, err := s.prepareTransport(context.Background(), s.Enclave(), t, verificationRetries)
	return err
}

func (s *SecureClient) prepareTransport(ctx context.Context, enclave string, t *refreshingTransport, retries int) (*enclaveState, error) {
	for {
		state, err := s.verifiedState(ctx, enclave, false, retries, t)
		if err != nil {
			return nil, err
		}
		if t == nil {
			return state, nil
		}
		s.stateMu.RLock()
		valid := state.valid()
		registered := state.transports[t] != nil
		s.stateMu.RUnlock()
		if !valid {
			continue
		}
		if registered {
			return state, nil
		}
		transport, err := t.buildTransport(state.VerifiedDocumentV3)
		if err != nil {
			return nil, err
		}
		s.stateMu.Lock()
		entry := s.entry(enclave)
		call := entry.refreshing
		if entry.state == state && call == nil && state.valid() {
			if state.transports == nil {
				state.transports = make(map[*refreshingTransport]http.RoundTripper)
			}
			if state.transports[t] != nil {
				s.stateMu.Unlock()
				closeIdleConnections(transport)
				return state, nil
			}
			state.transports[t] = transport
			s.stateMu.Unlock()
			return state, nil
		}
		s.stateMu.Unlock()
		closeIdleConnections(transport)
		if call != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-call.done:
			}
		}
	}
}

type refreshingTransport struct {
	client     *SecureClient
	build      func(*VerifiedDocumentV3) (http.RoundTripper, error)
	isKeyError func(error) bool
}

func (t *refreshingTransport) buildTransport(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
	transport, err := t.build(cloneVerification(verified))
	if transport == nil && err == nil {
		err = fmt.Errorf("transport builder returned nil")
	}
	if err != nil {
		closeIdleConnections(transport)
	}
	return transport, err
}

func (t *refreshingTransport) admit(ctx context.Context, selected *enclaveState) (http.RoundTripper, *enclaveState, error) {
	for {
		var state *enclaveState
		var err error
		if selected == nil {
			state, err = t.client.ready(ctx, t, nil)
		} else {
			state, err = t.client.prepareTransport(ctx, selected.EnclaveHost, t, verificationRetries)
		}
		if err != nil {
			return nil, nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		t.client.stateMu.RLock()
		transport := state.transports[t]
		valid := state.valid()
		t.client.stateMu.RUnlock()
		if valid {
			return transport, state, nil
		}
	}
}

func (t *refreshingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport, state, err := t.admit(req.Context(), nil)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := transport.RoundTrip(req)
	if err == nil || t.isKeyError == nil || !t.isKeyError(err) {
		return resp, err
	}
	t.client.invalidate(state)
	retry, bodyErr := resetRequestBody(req)
	if bodyErr != nil {
		return resp, errors.Join(bodyErr, err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	selected, refreshErr := t.client.ready(req.Context(), t, state)
	if refreshErr != nil {
		closeRequestBody(retry)
		return nil, errors.Join(refreshErr, err)
	}
	// Each explicit retry is a new admission. In-flight responses/streams keep
	// their original transport and are not canceled when its witnesses expire.
	transport, state, refreshErr = t.admit(req.Context(), selected)
	if refreshErr != nil {
		closeRequestBody(retry)
		return nil, errors.Join(refreshErr, err)
	}
	resp, retryErr := transport.RoundTrip(retry)
	if retryErr != nil {
		if t.isKeyError(retryErr) {
			t.client.invalidate(state)
		}
		return resp, errors.Join(retryErr, err)
	}
	return resp, nil
}

func (t *refreshingTransport) CloseIdleConnections() {
	t.client.stateMu.RLock()
	var transports []http.RoundTripper
	for _, entry := range t.client.enclaves {
		if entry.state != nil {
			transports = append(transports, entry.state.transports[t])
		}
	}
	t.client.stateMu.RUnlock()
	for _, transport := range transports {
		closeIdleConnections(transport)
	}
}

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

func resetRequestBody(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("cannot retry request after key rotation: body is not replayable")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	retry.Body = body
	return retry, nil
}

func isCertificateError(err error) bool {
	var certInvalidErr x509.CertificateInvalidError
	var unknownAuthErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certVerifyErr *tls.CertificateVerificationError
	return errors.Is(err, errCertMismatch) ||
		errors.As(err, &certInvalidErr) || errors.As(err, &unknownAuthErr) ||
		errors.As(err, &hostnameErr) || errors.As(err, &certVerifyErr)
}
