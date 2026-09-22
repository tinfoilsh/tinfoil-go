package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// NewTransport admits requests only with unexpired verification. build must
// bind its transport to the supplied attested keys. isKeyError identifies an
// error safe to retry after re-verification; nil disables key-rotation retries.
// All transports from this client share its verification and refresh state.
func (s *SecureClient) NewTransport(build func(*VerifiedDocumentV3) (http.RoundTripper, error), isKeyError func(error) bool) (http.RoundTripper, error) {
	if build == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("transport builder is required")}
	}
	t := &refreshingTransport{client: s, build: build, isKeyError: isKeyError}
	if _, _, err := t.admit(context.Background()); err != nil {
		return nil, err
	}
	return t, nil
}

type refreshingTransport struct {
	client     *SecureClient
	build      func(*VerifiedDocumentV3) (http.RoundTripper, error)
	isKeyError func(error) bool
	mu         sync.Mutex
	state      *VerifiedDocumentV3
	transport  http.RoundTripper
}

func (t *refreshingTransport) admit(ctx context.Context) (http.RoundTripper, *VerifiedDocumentV3, error) {
	for {
		state, err := t.client.verifiedState(ctx, nil, false)
		if err != nil {
			return nil, nil, err
		}
		t.mu.Lock()
		if t.state != state {
			transport, err := t.build(cloneVerification(state))
			if transport == nil && err == nil {
				err = fmt.Errorf("transport builder returned nil")
			}
			if err != nil {
				t.mu.Unlock()
				return nil, nil, err
			}
			// Verification may have advanced while we waited or built. Install
			// only the current snapshot, serialized with refresh publication.
			t.client.stateMu.RLock()
			if t.client.state != state {
				t.client.stateMu.RUnlock()
				t.mu.Unlock()
				closeIdleConnections(transport)
				continue
			}
			previous := t.transport
			t.state, t.transport = state, transport
			t.client.stateMu.RUnlock()
			closeIdleConnections(previous)
		}
		transport := t.transport
		t.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		// Construction/lock contention may have crossed the deadline. Admission
		// is the last check before delegation, even on a reused connection.
		if time.Now().Before(state.FreshnessExpiresAt) {
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
	t.client.invalidate(state)
	retry, bodyErr := resetRequestBody(req)
	if bodyErr != nil {
		return resp, errors.Join(err, bodyErr)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if _, refreshErr := t.client.verifiedState(req.Context(), state, true); refreshErr != nil {
		closeRequestBody(retry)
		return nil, errors.Join(refreshErr, err)
	}
	// Each explicit retry is a new admission. In-flight responses/streams keep
	// their original transport and are not canceled when its witnesses expire.
	transport, state, refreshErr := t.admit(req.Context())
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
	t.mu.Lock()
	defer t.mu.Unlock()
	closeIdleConnections(t.transport)
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
