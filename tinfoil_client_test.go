package tinfoil

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// TestClientStreamingChat tests the streaming version with default parameters
func TestClientStreamingChat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	client, err := NewClient(option.WithAPIKey(apiKey))
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)

	// Create a streaming chat completion request
	stream := client.Chat.Completions.NewStreaming(context.Background(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
		Model: "llama3-3-70b",
	})
	defer stream.Close()

	acc := openai.ChatCompletionAccumulator{}
	for stream.Next() {
		acc.AddChunk(stream.Current())
	}
	require.NoError(t, stream.Err())
	require.NotEmpty(t, acc.Choices)
	require.NotEmpty(t, acc.Choices[0].Message.Content)
}

func TestHTTPClient(t *testing.T) {
	t.Setenv(userCacheSecretEnv, "test-secret")
	client, err := NewClient()
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)

	httpClient := client.HTTPClient()
	require.NotNil(t, httpClient, "HTTPClient() should return a non-nil client")

	// The outermost transport binds requests to the enclave/proxy host; the
	// user-cache-secret layer injects into the body before the EHBP
	// re-verifying transport (the default mode) seals it.
	hostBound, ok := httpClient.Transport.(*hostBoundRoundTripper)
	require.True(t, ok, "HTTPClient transport should be hostBoundRoundTripper")
	ucs, ok := hostBound.transport.(*userCacheSecretTransport)
	require.True(t, ok, "inner transport should inject the user cache secret")
	_, ok = ucs.transport.(*ehbpReVerifyingTransport)
	require.True(t, ok, "sealing transport should be ehbpReVerifyingTransport")

	// Verify it returns the same instance (shared client)
	httpClient2 := client.HTTPClient()
	require.Same(t, httpClient, httpClient2, "HTTPClient() should return the same instance")
}

// TestClientIntegration_AudioTranscription mirrors the Python audio integration
// test: it transcribes a known clip through the high-level client over the
// default (EHBP) transport and checks the recognized text.
func TestClientIntegration_AudioTranscription(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	c, err := NewClient(option.WithAPIKey(apiKey))
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)

	audioFile, err := os.Open("testdata/jackhammer.wav")
	require.NoError(t, err)
	defer audioFile.Close()

	transcription, err := c.Audio.Transcriptions.New(context.Background(), openai.AudioTranscriptionNewParams{
		Model:    "whisper-large-v3-turbo",
		File:     audioFile,
		Language: openai.String("en"),
	})
	require.NoError(t, err)
	require.Contains(t, strings.ToLower(transcription.Text), "stale smell of old beer")
}

func TestIsCertificateError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some random error"),
			expected: false,
		},
		{
			name:     "ErrNoTLS",
			err:      client.ErrNoTLS,
			expected: true,
		},
		{
			name:     "wrapped ErrNoTLS",
			err:      errors.Join(errors.New("connection failed"), client.ErrNoTLS),
			expected: true,
		},
		{
			name:     "ErrCertMismatch",
			err:      client.ErrCertMismatch,
			expected: true,
		},
		{
			name:     "wrapped ErrCertMismatch",
			err:      errors.Join(errors.New("request failed"), client.ErrCertMismatch),
			expected: true,
		},
		{
			name:     "x509.CertificateInvalidError",
			err:      x509.CertificateInvalidError{Reason: x509.Expired},
			expected: true,
		},
		{
			name:     "x509.UnknownAuthorityError",
			err:      x509.UnknownAuthorityError{},
			expected: true,
		},
		{
			name:     "x509.HostnameError",
			err:      x509.HostnameError{Host: "example.com"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCertificateError(tt.err)
			require.Equal(t, tt.expected, result)
		})
	}
}
