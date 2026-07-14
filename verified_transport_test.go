package tinfoil

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubRoundTripper records the last request and returns an empty 200.
type stubRoundTripper struct {
	req *http.Request
}

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.req = req
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     make(http.Header),
	}, nil
}

func TestNewHostBoundTransportBindsOrigins(t *testing.T) {
	stub := &stubRoundTripper{}
	guarded, err := NewHostBoundTransport("enclave.example.com", "http://localhost:8080", stub)
	require.NoError(t, err)

	do := func(url string) error {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		resp, err := guarded.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
		return err
	}

	require.NoError(t, do("https://enclave.example.com/v1/models"))
	require.NoError(t, do("http://localhost:8080/v1/models"))

	stub.req = nil
	err = do("https://attacker.example.com/v1/models")
	require.Error(t, err, "a foreign origin must be refused")
	require.Nil(t, stub.req, "the wrapped transport must not see the refused request")
}

func TestNewHostBoundTransportRejectsInvalidBaseURL(t *testing.T) {
	_, err := NewHostBoundTransport("enclave.example.com", "ftp://proxy.example", &stubRoundTripper{})
	require.Error(t, err)
}

func TestNewVerifiedTransportRejectsInvalidConfig(t *testing.T) {
	t.Run("invalid base URL", func(t *testing.T) {
		_, err := NewVerifiedTransport(WithBaseURL("/v1"))
		require.Error(t, err)
	})

	t.Run("unknown transport mode", func(t *testing.T) {
		_, err := NewVerifiedTransport(WithEnclave("enclave.example.com"), WithTransport("bogus"))
		require.Error(t, err)
	})
}

// TestNewVerifiedTransport performs real router selection and attestation,
// mirroring TestNewClient, and pins that the returned transport is the bare
// sealing transport with no cache-secret or origin-binding layers.
func TestNewVerifiedTransport(t *testing.T) {
	t.Setenv(UserCacheSecretEnv, "must-not-appear-in-the-stack")

	vt, err := NewVerifiedTransport()
	require.NoError(t, err)
	require.NotEmpty(t, vt.Enclave())
	require.NotEmpty(t, vt.Repo())
	_, ok := vt.transport.(*ehbpReVerifyingTransport)
	require.True(t, ok, "expected the bare EHBP sealing transport, got %T", vt.transport)
}
