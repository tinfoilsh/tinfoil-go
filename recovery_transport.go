package tinfoil

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// recoveryTransport owns one application replay. Its underlying transport
// admits each attempt through the selected SecureClient's current state.
type recoveryTransport struct {
	transport http.RoundTripper
}

func (t *recoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if !client.IsKeyRejection(err) {
		return resp, err
	}
	retry, bodyErr := resetRequestBody(req)
	if bodyErr != nil {
		return resp, errors.Join(bodyErr, err)
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if cancelErr := req.Context().Err(); cancelErr != nil {
		closeRequestBody(retry)
		return nil, errors.Join(cancelErr, err)
	}
	resp, retryErr := t.transport.RoundTrip(retry)
	if retryErr != nil {
		return resp, errors.Join(retryErr, err)
	}
	return resp, nil
}

func (t *recoveryTransport) CloseIdleConnections() {
	if closer, ok := t.transport.(interface{ CloseIdleConnections() }); ok {
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
