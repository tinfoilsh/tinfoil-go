package transport

import (
	"errors"
	"fmt"
	"net/http"
)

// WithReplay re-sends a request once when next fails with an error retryable
// accepts, if the request's body can be read again. The routes pass
// IsKeyRejection: the rejection has already invalidated the verification, so
// the replay goes out under a fresh one.
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
	if !t.retryable(err) {
		return resp, err
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	retry, bodyErr := resetRequestBody(req)
	if bodyErr != nil {
		return nil, errors.Join(bodyErr, err)
	}
	if cancelErr := req.Context().Err(); cancelErr != nil {
		closeRequestBody(retry)
		return nil, errors.Join(cancelErr, err)
	}
	resp, retryErr := t.transport.RoundTrip(retry)
	if retryErr != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, errors.Join(retryErr, err)
	}
	return resp, nil
}

func (t *replayTransport) CloseIdleConnections() {
	closeIdleConnections(t.transport)
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
