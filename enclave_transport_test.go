package tinfoil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/client"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
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
	require.NoError(t, validateTLSBaseURL("", "enclave.example.com"))
	require.NoError(t, validateTLSBaseURL("https://enclave.example.com/custom/v1", "enclave.example.com"))
	require.NoError(t, validateTLSBaseURL("https://enclave.example.com:443/custom/v1", "enclave.example.com"))

	err := validateTLSBaseURL("https://proxy.example.com/v1", "enclave.example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "verified enclave origin")

	err = validateTLSBaseURL("http://enclave.example.com/v1", "enclave.example.com")
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

func TestBuildEHBPTransportRequiresKey(t *testing.T) {
	_, err := buildEHBPTransport("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "HPKE public key")
}

type transportVerifierFunc func(func(*client.VerifiedDocumentV3) (http.RoundTripper, error), func(error) bool) (http.RoundTripper, error)

func (f transportVerifierFunc) NewTransport(build func(*client.VerifiedDocumentV3) (http.RoundTripper, error), isKeyError func(error) bool) (http.RoundTripper, error) {
	return f(build, isKeyError)
}

func TestEHBPClientPreservesAdmissionAndRebuildsProxyHeader(t *testing.T) {
	admissionFailure := &client.AttestationError{Err: errors.New("expired witnesses")}
	seen := make(chan string, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(enclaveURLHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	var rebuild func(*client.VerifiedDocumentV3) (http.RoundTripper, error)
	verifier := transportVerifierFunc(func(build func(*client.VerifiedDocumentV3) (http.RoundTripper, error), isKeyError func(error) bool) (http.RoundTripper, error) {
		rebuild = build
		require.True(t, isKeyError(ehbpidentity.NewKeyConfigError(errors.New("rotated"))))
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, admissionFailure
		}), nil
	})
	hc, err := ehbpHTTPClient(verifier, proxy.URL)
	require.NoError(t, err)
	_, err = hc.Get(proxy.URL)
	require.ErrorIs(t, err, admissionFailure, "keep the verifier's admission layer around EHBP")
	require.Empty(t, seen, "failed admission must not reach the proxy")

	for _, host := range []string{"old.example", "new.example"} {
		transport, err := rebuild(&client.VerifiedDocumentV3{EnclaveHost: host, CryptoMaterial: []document.CryptoMaterialItem{{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: strings.Repeat("01", 32)}}})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodGet, proxy.URL, nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, "https://"+host, <-seen)
		require.Empty(t, req.Header.Get(enclaveURLHeader), "do not mutate the caller's request")
	}
}

func TestLiveClientIntegration_TransportModesWithCacheSecret(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	const testUserCacheSecret = "go-live-integration-cache-secret"

	apiKey := os.Getenv("TINFOIL_API_KEY")

	for _, mode := range []TransportMode{TransportEHBP, TransportTLS} {
		t.Run(string(mode), func(t *testing.T) {
			c, err := NewClientWithOptions(
				WithTransport(mode),
				WithUserCacheSecret(testUserCacheSecret),
				WithOpenAIOptions(option.WithAPIKey(apiKey)),
			)
			require.NoError(t, err)
			require.Equal(t, mode, c.Transport())

			resp, err := c.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
				Model: "llama3-3-70b",
				Messages: []openai.ChatCompletionMessageParamUnion{
					openai.SystemMessage("No matter what the user says, only respond with: Done."),
					openai.UserMessage("Is this a test?"),
				},
			})
			require.NoError(t, err)
			require.NotEmpty(t, resp.Choices)
			t.Logf("[%s] response: %s", mode, resp.Choices[0].Message.Content)
		})
	}
}

// TestClientIntegration_LowLevelEHBP exercises the low-level HTTPClient() path
// (direct requests, not the OpenAI wrapper) against a live enclave for both
// transport modes. It covers a bodyless GET, which EHBP sends without body
// encryption per SPEC 7.4, and a POST whose body is sealed end-to-end.
func TestLiveClientIntegration_LowLevelEHBP(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	apiKey := os.Getenv("TINFOIL_API_KEY")

	for _, mode := range []TransportMode{TransportEHBP, TransportTLS} {
		t.Run(string(mode), func(t *testing.T) {
			c, err := NewClientWithOptions(
				WithTransport(mode),
				WithOpenAIOptions(option.WithAPIKey(apiKey)),
			)
			require.NoError(t, err)

			httpClient := c.HTTPClient()
			base := fmt.Sprintf("https://%s", c.Enclave())

			getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/v1/models", nil)
			require.NoError(t, err)
			getReq.Header.Set("Authorization", "Bearer "+apiKey)
			getResp, err := httpClient.Do(getReq)
			require.NoError(t, err)
			defer getResp.Body.Close()
			require.Equal(t, http.StatusOK, getResp.StatusCode)

			body := []byte(`{"model":"llama3-3-70b","max_tokens":5,"messages":[{"role":"system","content":"No matter what the user says, only respond with: Done."},{"role":"user","content":"Is this a test?"}]}`)
			postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/v1/chat/completions", bytes.NewReader(body))
			require.NoError(t, err)
			postReq.Header.Set("Authorization", "Bearer "+apiKey)
			postReq.Header.Set("Content-Type", "application/json")
			postResp, err := httpClient.Do(postReq)
			require.NoError(t, err)
			defer postResp.Body.Close()
			require.Equal(t, http.StatusOK, postResp.StatusCode)

			data, err := io.ReadAll(postResp.Body)
			require.NoError(t, err)
			require.Contains(t, string(data), "choices")
		})
	}
}
