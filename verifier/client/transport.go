package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// NewTransport admits requests only with unexpired verification. build must
// bind its transport to the supplied attested keys. isKeyError identifies an
// error safe to retry after re-verification; nil disables key-rotation retries.
// All transports from this client share its verification and refresh state.
// build receives a detached result and must only construct its bound transport;
// it must not call the client's verification, transport setup, or request methods.
func (s *SecureClient) NewTransport(build func(*VerifiedDocumentV3) (http.RoundTripper, error), isKeyError func(error) bool) (http.RoundTripper, error) {
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
	for {
		state, err := s.verifiedState(context.Background(), nil, false)
		if err != nil {
			return err
		}
		s.stateMu.RLock()
		registered := state.transports[t] != nil
		s.stateMu.RUnlock()
		if registered {
			return nil
		}
		transport, err := t.buildTransport(state.VerifiedDocumentV3)
		if err != nil {
			return err
		}
		s.stateMu.Lock()
		call := s.refreshing
		if s.state == state && call == nil && time.Now().Before(state.FreshnessExpiresAt) {
			if state.transports == nil {
				state.transports = make(map[*refreshingTransport]http.RoundTripper)
			}
			if existing := state.transports[t]; existing != nil {
				s.stateMu.Unlock()
				closeIdleConnections(transport)
				return nil
			}
			state.transports[t] = transport
			s.stateMu.Unlock()
			return nil
		}
		s.stateMu.Unlock()
		closeIdleConnections(transport)
		// Register only against the completed refresh, so every later refresh
		// includes this transport in the state it publishes.
		if call != nil {
			<-call.done
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

func (t *refreshingTransport) admit(ctx context.Context) (http.RoundTripper, *enclaveState, error) {
	for {
		state, err := t.client.verifiedState(ctx, nil, false)
		if err != nil {
			return nil, nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		t.client.stateMu.RLock()
		transport := state.transports[t]
		valid := time.Now().Before(state.FreshnessExpiresAt)
		t.client.stateMu.RUnlock()
		if valid {
			return transport, state, nil
		}
	}
}

func (t *refreshingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport, state, err := t.admit(req.Context())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := transport.RoundTrip(req)
	if err == nil || t.isKeyError == nil || !t.isKeyError(err) {
		return resp, err
	}
	retry, bodyErr := resetRequestBody(req)
	if bodyErr != nil {
		return resp, err
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if _, refreshErr := t.client.verifiedState(req.Context(), state, true); refreshErr != nil {
		closeRequestBody(retry)
		return nil, errors.Join(err, refreshErr)
	}
	// Each explicit retry is a new admission. In-flight responses/streams keep
	// their original transport and are not canceled when its witnesses expire.
	transport, _, refreshErr := t.admit(req.Context())
	if refreshErr != nil {
		closeRequestBody(retry)
		return nil, errors.Join(err, refreshErr)
	}
	return transport.RoundTrip(retry)
}

func (t *refreshingTransport) CloseIdleConnections() {
	t.client.stateMu.RLock()
	transport := t.client.state.transports[t]
	t.client.stateMu.RUnlock()
	closeIdleConnections(transport)
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
