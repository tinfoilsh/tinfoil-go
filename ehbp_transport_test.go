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
	"time"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
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

	require.Equal(t, "https://proxy.example.com/", cfg.baseURL)
	require.True(t, cfg.baseURLSet)
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

func TestNewClientWithOptionsRejectsInvalidFreshnessMaxAge(t *testing.T) {
	for _, enclave := range []string{"", "enclave.example"} {
		for _, maxAge := range []time.Duration{-time.Nanosecond, -time.Hour} {
			c, err := NewClientWithOptions(WithEnclave(enclave), WithVerificationOptions(client.VerificationOptions{
				FreshnessMaxAge: maxAge,
				PinnedRegisters: &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: strings.Repeat("ab", 48)}},
			}))
			require.Nil(t, c)
			require.ErrorContains(t, err, "freshness maximum age must not be negative")
		}
	}
}

func TestClientFreshnessMaxAge(t *testing.T) {
	host, repo := os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO")
	if host == "" || repo == "" {
		t.Skip("TINFOIL_ENCLAVE or TINFOIL_REPO not set")
	}
	for _, mode := range []TransportMode{TransportEHBP, TransportTLS} {
		for _, enclave := range []string{"", host} {
			t.Run(string(mode)+"/"+enclave, func(t *testing.T) {
				opts := []ClientOption{WithTransport(mode), WithEnclave(enclave), WithVerificationOptions(client.VerificationOptions{FreshnessMaxAge: time.Nanosecond})}
				if enclave != "" {
					opts = append(opts, WithRepo(repo))
				}
				c, err := NewClientWithOptions(opts...)
				require.Nil(t, c)
				require.ErrorContains(t, err, "freshness witness is stale")
				c, err = NewClientWithOptions(append(opts, WithVerificationOptions(client.VerificationOptions{}))...)
				require.NoError(t, err)
				require.NotNil(t, c)
				pins := c.VerificationDocument().EnclaveMeasurement.Measurement
				pins.Registers[0] = strings.Repeat("ab", 48)
				c, err = NewClientWithOptions(append(opts, WithVerificationOptions(client.VerificationOptions{PinnedRegisters: pins}))...)
				require.Nil(t, c)
				require.ErrorContains(t, err, "cpu evidence")
			})
		}
	}
}

func TestNewClientWithOptionsRequiresEnclaveForCustomRepo(t *testing.T) {
	for _, opt := range []ClientOption{
		WithRepo("org/repo"),
		WithRepo(defaultConfigRepo + "@v1"),
		WithRepo(defaultConfigRepo + "@sha256:" + strings.Repeat("ab", 32)),
	} {
		c, err := NewClientWithOptions(opt)
		require.Nil(t, c)
		require.ErrorContains(t, err, "requires an enclave")
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

type transportVerifierFunc func(func(*client.GroundTruth) (http.RoundTripper, error), func(error) bool) (http.RoundTripper, error)

func (f transportVerifierFunc) NewTransport(build func(*client.GroundTruth) (http.RoundTripper, error), isKeyError func(error) bool) (http.RoundTripper, error) {
	return f(build, isKeyError)
}

func TestEHBPClientPreservesAdmissionAndRebuildsProxyHeader(t *testing.T) {
	seen := make(chan string, 2)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(enclaveURLHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	var rebuild func(*client.GroundTruth) (http.RoundTripper, error)
	verifier := transportVerifierFunc(func(build func(*client.GroundTruth) (http.RoundTripper, error), isKeyError func(error) bool) (http.RoundTripper, error) {
		rebuild = build
		require.True(t, isKeyError(ehbpidentity.NewKeyConfigError(errors.New("rotated"))))
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, client.ErrFreshnessExpired
		}), nil
	})
	hc, err := ehbpHTTPClient(verifier, proxy.URL)
	require.NoError(t, err)
	_, err = hc.Get(proxy.URL)
	require.ErrorIs(t, err, client.ErrFreshnessExpired, "keep the verifier's admission layer around EHBP")
	require.Empty(t, seen, "failed admission must not reach the proxy")

	for _, host := range []string{"old.example", "new.example"} {
		transport, err := rebuild(&client.GroundTruth{EnclaveHost: host, HPKEPublicKey: strings.Repeat("01", 32)})
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

// Bodyless EHBP requests use no body encryption, per SPEC 7.4.
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
