package tinfoil

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
)

// TestClientStreamingChat tests the streaming version with default parameters
func TestClientStreamingChat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	client, err := NewClient(WithOpenAIOptions(option.WithAPIKey(apiKey)))
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
	if err := stream.Err(); err != nil {
		// openai-go emits a JSON error for an empty SSE event before [DONE].
		var syntaxErr *json.SyntaxError
		require.ErrorAs(t, err, &syntaxErr)
		require.Zero(t, syntaxErr.Offset, "only tolerate an empty SSE event")
		require.EqualError(t, err, "unexpected end of JSON input")
	}
	require.NotEmpty(t, acc.Choices)
	require.NotEmpty(t, acc.Choices[0].Message.Content)
	require.NotEmpty(t, acc.Choices[0].FinishReason)
}

func TestHTTPClient(t *testing.T) {
	t.Setenv(userCacheSecretEnv, "test-secret")
	client, err := NewClient()
	require.NoError(t, err)

	httpClient := client.HTTPClient()
	require.NotNil(t, httpClient, "HTTPClient() should return a non-nil client")

	// The outermost transport binds requests to the enclave/proxy host; the
	// user-cache-secret layer injects into the body before shared freshness
	// admission and EHBP sealing. The EHBP builder's admission and proxy-header
	// behavior is covered by TestEHBPClientPreservesAdmissionAndRebuildsProxyHeader.
	hostBound, ok := httpClient.Transport.(*hostBoundRoundTripper)
	require.True(t, ok, "HTTPClient transport should be hostBoundRoundTripper")
	ucs, ok := hostBound.transport.(*userCacheSecretTransport)
	require.True(t, ok, "inner transport should inject the user cache secret")
	require.NotNil(t, ucs.transport)

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

	c, err := NewClient(WithOpenAIOptions(option.WithAPIKey(apiKey)))
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
