package tinfoil

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOriginOfNormalizesDefaultPorts(t *testing.T) {
	tests := []struct {
		rawURL string
		want   string
	}{
		{"https://enclave.example.com:443/v1", "https://enclave.example.com"},
		{"http://proxy.example.com:80/v1", "http://proxy.example.com"},
		{"https://enclave.example.com:8443/v1", "https://enclave.example.com:8443"},
		{"http://[::1]:80/v1", "http://[::1]"},
		{"http://[::1]:8080/v1", "http://[::1]:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			origin, err := originOf(tt.rawURL)
			require.NoError(t, err)
			require.Equal(t, tt.want, origin)
		})
	}
}

func TestHostBoundRoundTripperAllowsEnclaveAndProxy(t *testing.T) {
	origins, err := allowedOrigins("enclave.example.com", "http://proxy.example.com/v1/")
	require.NoError(t, err)

	var calls int
	inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return newResponse(http.StatusOK, "ok"), nil
	})
	rt := &hostBoundRoundTripper{allowedOrigins: origins, enclave: "enclave.example.com", transport: inner}

	for _, target := range []string{
		"https://enclave.example.com/v1/models",
		"https://enclave.example.com:443/v1/models",
		"http://proxy.example.com/v1/chat/completions",
		"http://proxy.example.com:80/v1/chat/completions",
	} {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		require.NoError(t, err)
		resp, err := rt.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
	require.Equal(t, 4, calls)
}

func TestHostBoundRoundTripperRejectsForeignHostAndScheme(t *testing.T) {
	origins, err := allowedOrigins("enclave.example.com", "")
	require.NoError(t, err)
	inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("inner transport must not be called for a rejected request")
		return nil, nil
	})
	rt := &hostBoundRoundTripper{allowedOrigins: origins, enclave: "enclave.example.com", transport: inner}

	foreign, err := http.NewRequest(http.MethodGet, "https://evil.example.com/v1/models", nil)
	require.NoError(t, err)
	_, err = rt.RoundTrip(foreign)
	require.Error(t, err)
	require.Contains(t, err.Error(), "evil.example.com")

	plaintext, err := http.NewRequest(http.MethodGet, "http://enclave.example.com/v1/models", nil)
	require.NoError(t, err)
	_, err = rt.RoundTrip(plaintext)
	require.Error(t, err)
	require.Contains(t, err.Error(), "http://enclave.example.com")

	unsupported, err := http.NewRequest(http.MethodGet, "ftp://enclave.example.com/v1/models", nil)
	require.NoError(t, err)
	_, err = rt.RoundTrip(unsupported)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ftp://enclave.example.com")
}
