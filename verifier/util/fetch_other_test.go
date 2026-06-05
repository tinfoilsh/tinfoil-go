package util

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

type stubTransport struct{ resp *http.Response }

func (s *stubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return s.resp, nil
}

// withStubResponse points the default client at a stub returning resp and
// restores the original transport afterwards.
func withStubResponse(t *testing.T, resp *http.Response) {
	t.Helper()
	original := http.DefaultClient.Transport
	http.DefaultClient.Transport = &stubTransport{resp: resp}
	t.Cleanup(func() { http.DefaultClient.Transport = original })
}

func newStubResponse(status int, body *closeTrackingBody) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       body,
		Header:     make(http.Header),
	}
}

func TestPostClosesBodyOnNon2xx(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("error details")}
	withStubResponse(t, newStubResponse(http.StatusInternalServerError, body))

	_, _, err := Post("http://enclave.example/attestation", "application/json", []byte("{}"))
	require.Error(t, err)
	require.True(t, body.closed, "response body must be closed on a non-2xx response")
}

func TestGetClosesBodyOnNon2xx(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("error details")}
	withStubResponse(t, newStubResponse(http.StatusBadGateway, body))

	_, _, err := Get("http://enclave.example/attestation")
	require.Error(t, err)
	require.True(t, body.closed, "response body must be closed on a non-2xx response")
}

func TestPostReturnsBodyOn2xx(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("payload")}
	withStubResponse(t, newStubResponse(http.StatusOK, body))

	got, _, err := Post("http://enclave.example/attestation", "application/json", []byte("{}"))
	require.NoError(t, err)
	require.Equal(t, "payload", string(got))
	require.True(t, body.closed, "response body must be closed after a successful read")
}
