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
func TestClientIntegration_TransportModes(t *testing.T) {
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
