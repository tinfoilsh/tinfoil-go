package transport

import (
	"fmt"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

// WithReplay re-sends a request once when next fails with an error that
// retryable accepts, if the request's body can be read again. The routes pass
// IsKeyRejection: the rejection has already invalidated the verification, so
// the replay goes out under a fresh one.
//
// Like net/http.Transport, it reports one error: a network error when the
// body can't be read again, the context's error when the caller cancels
// before the replay, and the replay's own error when the replay fails.
func WithReplay(next http.RoundTripper, retryable func(error) bool) http.RoundTripper {
	return &replayTransport{transport: next, retryable: retryable}
}

// replayTransport owns one application replay.
type replayTransport struct {
	transport http.RoundTripper
	retryable func(error) bool
}

func (t *replayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if err == nil || !t.retryable(err) {
		return resp, err
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	retry, bodyErr := resetRequestBody(req)
	if retry == nil {
		return nil, errs.Network(&unreplayableError{bodyErr: bodyErr, rejection: err})
	}
	if cancelErr := req.Context().Err(); cancelErr != nil {
		closeRequestBody(retry)
		return nil, cancelErr
	}
	resp, retryErr := t.transport.RoundTrip(retry)
	if retryErr != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, retryErr
	}
	return resp, nil
}

func (t *replayTransport) CloseIdleConnections() {
	closeIdleConnections(t.transport)
}

// resetRequestBody returns a copy of req with a fresh body, or nil and the
// error that GetBody returned when the body can't be read again. Both are nil
// when req has no GetBody.
func resetRequestBody(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	if req.GetBody == nil {
		return nil, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	retry.Body = body
	return retry, nil
}

// unreplayableError reports a request that the enclave rejected for a rotated
// key and that can't be sent again because its body can't be read a second
// time. Its message includes the rejection, but errors.Is and errors.As don't
// reach it: the rejection may carry a category of its own, and a routine key
// rotation that the SDK couldn't recover from is a network error, not an
// attestation failure. IsKeyRejection still reports it, since the rejection
// has invalidated the verification all the same.
type unreplayableError struct {
	// bodyErr is the error that GetBody returned, or nil if the request
	// has no GetBody.
	bodyErr error
	// rejection is the key rejection that the request failed with.
	rejection error
}

func (e *unreplayableError) Error() string {
	msg := "enclave key rotated; the request body can't be replayed"
	if e.bodyErr != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.bodyErr)
	}
	return fmt.Sprintf("%s (key rejection: %v)", msg, e.rejection)
}

// Unwrap returns the error that GetBody returned, if any, but not the
// rejection.
func (e *unreplayableError) Unwrap() error     { return e.bodyErr }
func (e *unreplayableError) KeyRejected() bool { return true }
