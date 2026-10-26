package transport

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func TestValidateTLSBaseURL(t *testing.T) {
	require.NoError(t, ValidateTLSBaseURL("", "enclave.example.com"))
	require.NoError(t, ValidateTLSBaseURL("https://enclave.example.com/custom/v1", "enclave.example.com"))
	require.NoError(t, ValidateTLSBaseURL("https://enclave.example.com:443/custom/v1", "enclave.example.com"))

	err := ValidateTLSBaseURL("https://proxy.example.com/v1", "enclave.example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "verified enclave origin")

	err = ValidateTLSBaseURL("http://enclave.example.com/v1", "enclave.example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "verified enclave origin")
}

func TestEnclaveURLHeaderValue(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		enclave string
		wantVal string
		wantOK  bool
	}{
		{"proxy different origin", "https://proxy.example.com/", "enclave.example.com", "https://enclave.example.com", true},
		{"proxy keeps path but different origin", "https://proxy.example.com/api/v1/", "enclave.example.com", "https://enclave.example.com", true},
		{"base url is the enclave itself", "https://enclave.example.com/v1/", "enclave.example.com", "", false},
		{"base url uses explicit default port", "https://enclave.example.com:443/v1/", "enclave.example.com", "", false},
		{"no base url", "", "enclave.example.com", "", false},
		{"no enclave", "https://proxy.example.com/", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, ok := enclaveURLHeaderValue(tt.baseURL, tt.enclave)
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.wantVal, val)
		})
	}
}

func TestEnclaveURLHeaderTransportInjectsHeader(t *testing.T) {
	var seen string
	inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = req.Header.Get(enclaveURLHeader)
		return newResponse(http.StatusOK, "ok"), nil
	})

	transport := &enclaveURLHeaderTransport{
		enclaveURL: "https://enclave.example.com",
		transport:  inner,
	}

	req, err := http.NewRequest(http.MethodPost, "https://proxy.example.com/v1/chat/completions", bytes.NewBufferString("payload"))
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "https://enclave.example.com", seen, "the proxy must receive the enclave URL header")
	require.Empty(t, req.Header.Get(enclaveURLHeader), "the original request must not be mutated")
}

func TestWithEnclaveURLPreservesAdmissionAndProxyHeader(t *testing.T) {
	seen := make(chan string, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(enclaveURLHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	admissionFailure := &enclave.AttestationError{Err: errors.New("expired witnesses")}
	hc := &http.Client{Transport: withEnclaveURL(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, admissionFailure
	}), "enclave.example", proxy.URL)}
	_, err := hc.Get(proxy.URL)
	require.ErrorIs(t, err, admissionFailure, "keep the bound transport's admission errors")
	require.Empty(t, seen, "failed admission must not reach the proxy")

	// Every request, including retries, keeps routing to the client's enclave.
	// The header sits above the bound transport, so re-verification, which only
	// rebuilds the transport below it, can't drop it.
	transport := withEnclaveURL(http.DefaultTransport, "enclave.example", proxy.URL)
	for range 2 {
		req, err := http.NewRequest(http.MethodGet, proxy.URL, nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, "https://enclave.example", <-seen)
		require.Empty(t, req.Header.Get(enclaveURLHeader), "do not mutate the caller's request")
	}

	_, wrapped := withEnclaveURL(http.DefaultTransport, "enclave.example", "https://enclave.example/v1/").(*enclaveURLHeaderTransport)
	require.False(t, wrapped, "a base URL on the enclave's origin needs no header")
}
