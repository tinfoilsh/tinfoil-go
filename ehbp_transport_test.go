package tinfoil

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

// roundTripFunc adapts a function to an http.RoundTripper.
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

func TestClientOptionsDefaults(t *testing.T) {
	cfg := &clientConfig{
		repo:      defaultConfigRepo,
		transport: defaultTransportMode,
	}
	require.Equal(t, TransportEHBP, cfg.transport)
	require.Equal(t, "tinfoilsh/confidential-model-router", cfg.repo)
}

func TestClientOptionsApply(t *testing.T) {
	cfg := &clientConfig{}
	for _, opt := range []ClientOption{
		WithEnclave("enclave.example.com"),
		WithRepo("org/repo"),
		WithTransport(TransportTLS),
		WithOpenAIOptions(option.WithAPIKey("k1"), option.WithAPIKey("k2")),
	} {
		opt(cfg)
	}

	require.Equal(t, "enclave.example.com", cfg.enclave)
	require.Equal(t, "org/repo", cfg.repo)
	require.Equal(t, TransportTLS, cfg.transport)
	require.Len(t, cfg.openaiOpts, 2)
}

func TestProxyClientOptionsApply(t *testing.T) {
	cfg := &clientConfig{}
	WithBaseURL("https://proxy.example.com/")(cfg)
	WithAttestationBundleURL("https://proxy.example.com")(cfg)

	require.Equal(t, "https://proxy.example.com/", cfg.baseURL)
	require.True(t, cfg.baseURLSet)
	require.Equal(t, "https://proxy.example.com", cfg.attestationBundleURL)
}

func TestNewClientWithOptionsRejectsInvalidBaseURL(t *testing.T) {
	for _, baseURL := range []string{"", "proxy.example.com", "ftp://proxy.example.com", "://"} {
		t.Run(baseURL, func(t *testing.T) {
			_, err := NewClientWithOptions(WithBaseURL(baseURL))
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid base URL")
		})
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

// TestEHBPReVerifyingTransportRefreshesEnclaveHeaderOnRotation verifies that
// after a key rotation triggers re-verification, the retried request carries the
// header for the newly verified enclave rather than a stale one. The header
// transport is the inner layer that reverify rebuilds, so the retry flows
// through the refreshed value.
func TestEHBPReVerifyingTransportRefreshesEnclaveHeaderOnRotation(t *testing.T) {
	keyErr := ehbpidentity.NewKeyConfigError(fmt.Errorf("key configuration mismatch"))

	var firstHeader, retryHeader string
	firstInner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		firstHeader = req.Header.Get(enclaveURLHeader)
		return nil, keyErr
	})
	secondInner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		retryHeader = req.Header.Get(enclaveURLHeader)
		return newResponse(http.StatusOK, "recovered"), nil
	})

	first := &enclaveURLHeaderTransport{enclaveURL: "https://old.example.com", transport: firstInner}
	second := &enclaveURLHeaderTransport{enclaveURL: "https://new.example.com", transport: secondInner}

	transport := &ehbpReVerifyingTransport{transport: first}
	transport.reverify = func() (http.RoundTripper, error) {
		transport.mu.Lock()
		transport.transport = second
		transport.mu.Unlock()
		return second, nil
	}

	req, err := http.NewRequest(http.MethodPost, "https://proxy.example.com/v1/x", bytes.NewBufferString("payload"))
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "https://old.example.com", firstHeader, "first attempt carries the original enclave header")
	require.Equal(t, "https://new.example.com", retryHeader, "retry must carry the refreshed enclave header after re-verification")
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

func TestBuildEHBPTransportRequiresKey(t *testing.T) {
	_, err := buildEHBPTransport("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "HPKE public key")
}

func TestEHBPReVerifyingTransportPassesThrough(t *testing.T) {
	var calls int
	inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return newResponse(http.StatusOK, "ok"), nil
	})

	transport := &ehbpReVerifyingTransport{
		transport: inner,
		reverify: func() (http.RoundTripper, error) {
			t.Fatalf("reverify should not be called on success")
			return nil, nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://enclave.example.com/v1/models", nil)
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, 1, calls)
}

func TestEHBPReVerifyingTransportIgnoresOtherErrors(t *testing.T) {
	otherErr := fmt.Errorf("connection refused")
	inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, otherErr
	})

	transport := &ehbpReVerifyingTransport{
		transport: inner,
		reverify: func() (http.RoundTripper, error) {
			t.Fatalf("reverify should not be called for non key-config errors")
			return nil, nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://enclave.example.com/v1/models", nil)
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.ErrorIs(t, err, otherErr)
}

func TestEHBPReVerifyingTransportRetriesOnKeyRotation(t *testing.T) {
	keyErr := ehbpidentity.NewKeyConfigError(fmt.Errorf("key configuration mismatch"))

	var firstBody, retryBody string
	firstTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		firstBody = string(b)
		return nil, keyErr
	})
	retryTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		retryBody = string(b)
		return newResponse(http.StatusOK, "recovered"), nil
	})

	var reverifyCalls int
	transport := &ehbpReVerifyingTransport{transport: firstTransport}
	transport.reverify = func() (http.RoundTripper, error) {
		reverifyCalls++
		transport.mu.Lock()
		transport.transport = retryTransport
		transport.mu.Unlock()
		return retryTransport, nil
	}

	req, err := http.NewRequest(http.MethodPost, "https://enclave.example.com/v1/chat/completions", bytes.NewBufferString("payload"))
	require.NoError(t, err)

	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, 1, reverifyCalls)
	require.Equal(t, "payload", firstBody)
	require.Equal(t, "payload", retryBody, "the request body must be replayed on retry")
}

// TestEHBPReVerifyingTransportSerializesReverify drives many concurrent
// RoundTrip calls through a transport that always reports a key rotation,
// asserting that re-verification (which mutates shared, unsynchronized
// SecureClient state) runs exactly once. Run with -race to detect any data
// race on that shared state.
func TestEHBPReVerifyingTransportSerializesReverify(t *testing.T) {
	keyErr := ehbpidentity.NewKeyConfigError(fmt.Errorf("key configuration mismatch"))
	rotated := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return newResponse(http.StatusOK, "ok"), nil
	})

	transport := &ehbpReVerifyingTransport{
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, keyErr
		}),
	}

	// sharedState models the unsynchronized writes SecureClient.Verify performs.
	// reverifyOnce must serialize and coalesce calls so this is touched once.
	var sharedState int
	transport.reverify = func() (http.RoundTripper, error) {
		sharedState++
		return rotated, nil
	}

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodGet, "https://enclave.example.com/v1/models", nil)
			if !assert.NoError(t, err) {
				return
			}
			resp, err := transport.RoundTrip(req)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}()
	}
	wg.Wait()

	require.Equal(t, 1, sharedState, "re-verification should be coalesced to a single run")
}

func TestEHBPReVerifyingTransportSurfacesOriginalErrorWhenReverifyFails(t *testing.T) {
	keyErr := ehbpidentity.NewKeyConfigError(fmt.Errorf("key configuration mismatch"))
	inner := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, keyErr
	})

	transport := &ehbpReVerifyingTransport{
		transport: inner,
		reverify: func() (http.RoundTripper, error) {
			return nil, fmt.Errorf("attestation failed")
		},
	}

	req, err := http.NewRequest(http.MethodPost, "https://enclave.example.com/v1/chat/completions", bytes.NewBufferString("payload"))
	require.NoError(t, err)

	_, err = transport.RoundTrip(req)
	require.True(t, ehbpidentity.IsKeyConfigError(err), "should surface the original key-config error")
}

func TestResetRequestBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://enclave.example.com/v1/chat/completions", bytes.NewBufferString("payload"))
	require.NoError(t, err)

	// Consume the body as the first attempt would.
	_, err = io.ReadAll(req.Body)
	require.NoError(t, err)

	retry, err := resetRequestBody(req)
	require.NoError(t, err)

	b, err := io.ReadAll(retry.Body)
	require.NoError(t, err)
	require.Equal(t, "payload", string(b))
}

func TestResetRequestBodyNotReplayable(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://enclave.example.com/v1/chat/completions", io.NopCloser(bytes.NewBufferString("payload")))
	require.NoError(t, err)
	req.GetBody = nil

	_, err = resetRequestBody(req)
	require.Error(t, err)
}

func TestResetRequestBodyNoBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://enclave.example.com/v1/models", nil)
	require.NoError(t, err)

	retry, err := resetRequestBody(req)
	require.NoError(t, err)
	require.Same(t, req, retry)
}

// TestClientIntegration_TransportModes exercises NewClientWithOptions against a
// live enclave for both transport modes.
func TestClientIntegration_TransportModesWithCacheSecret(t *testing.T) {
	const testUserCacheSecret = "go-live-integration-cache-secret"

	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

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
func TestClientIntegration_LowLevelEHBP(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

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

// TestClientIntegration_AttestationBundle exercises the attestation-through-proxy
// path against the live ATC bundle endpoint: the bundle is fetched and verified
// client-side, the enclave host is taken from the verified bundle, and a chat
// completion is sent end-to-end over the EHBP transport.
func TestClientIntegration_AttestationBundle(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	c, err := NewClientWithOptions(
		WithAttestationBundleURL("https://atc.tinfoil.sh"),
		WithOpenAIOptions(option.WithAPIKey(apiKey)),
	)
	require.NoError(t, err)
	require.NotEmpty(t, c.Enclave(), "enclave host should come from the verified bundle")

	resp, err := c.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model: "llama3-3-70b",
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Choices)
	t.Logf("bundle enclave: %s, response: %s", c.Enclave(), resp.Choices[0].Message.Content)
}

func TestClientIntegration_EnclaveSpecificBundle(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	// Learn a valid enclave from the default bundle, then request a bundle
	// assembled specifically for it (POST path).
	def, err := NewClientWithOptions(
		WithAttestationBundleURL("https://atc.tinfoil.sh"),
		WithOpenAIOptions(option.WithAPIKey(apiKey)),
	)
	require.NoError(t, err)
	enclave := def.Enclave()
	require.NotEmpty(t, enclave)

	c, err := NewClientWithOptions(
		WithEnclave(enclave),
		WithAttestationBundleURL("https://atc.tinfoil.sh"),
		WithOpenAIOptions(option.WithAPIKey(apiKey)),
	)
	require.NoError(t, err)
	require.Equal(t, enclave, c.Enclave())

	resp, err := c.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model: "llama3-3-70b",
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Choices)
}

func TestNewClientWithOptionsRejectsRepoWithoutEnclave(t *testing.T) {
	_, err := NewClientWithOptions(WithRepo("tinfoilsh/confidential-llama3-3-70b"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "needs an enclave to verify")

	// Naming the default repo explicitly is not a downgrade: it is what the fallback verifies against.
	_, err = NewClientWithOptions(WithRepo(defaultConfigRepo), WithEnclave("enclave.example.com"))
	require.Error(t, err) // no such enclave, but not the configuration error
	require.NotContains(t, err.Error(), "needs an enclave to verify")
}
