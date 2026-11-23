package tinfoil

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

func TestNewClientDiscoversUnderItsContext(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	synctest.Test(t, func(t *testing.T) {
		http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("no network in this test")
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c, err := NewClient(ctx)
		require.Nil(t, c)
		require.ErrorIs(t, err, context.Canceled)
	})
}

// NewClient returns the router constructor's error as it is, without a message
// of its own: an SDK error in exactly one category. A verification that failed
// again when it was retried reports its first attempt in its message, so the
// SDK error is the one that errors.As finds.
func TestNewClientReturnsTheRouterError(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	synctest.Test(t, func(t *testing.T) {
		http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("no network in this test")
		})
		c, err := NewClient(context.Background())
		require.Nil(t, c)
		var sdkError *Error
		require.ErrorAs(t, err, &sdkError)
		require.True(t, strings.HasPrefix(err.Error(), ErrNetwork.Error()+": "), "no message ahead of the SDK error's: %v", err)
		testutil.RequireCategory(t, err, ErrNetwork)
	})
}

func TestLiveClientStreamingChat(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	apiKey := os.Getenv("TINFOIL_API_KEY")

	client, err := NewClient(context.Background(), option.WithAPIKey(apiKey))
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

func TestLiveHTTPClient(t *testing.T) {
	testutil.RequireLive(t)
	client, err := NewClient(context.Background())
	require.NoError(t, err)

	httpClient, ok := client.HTTPClient().(*RouterHTTPClient)
	require.True(t, ok, "NewClient sends through a router client")

	_, err = httpClient.Get("https://unrelated.example")
	require.ErrorIs(t, err, ErrConfiguration, "the HTTP client must refuse unrelated origins")

	// Verify it returns the same instance (shared client)
	httpClient2 := client.HTTPClient()
	require.Same(t, AttestedHTTPClient(httpClient), httpClient2, "HTTPClient() should return the same instance")
}

// TestLiveClientIntegration_AudioTranscription mirrors the Python audio integration
// test: it transcribes a known clip through the high-level client over the
// default (EHBP) transport and checks the recognized text.
func TestLiveClientIntegration_AudioTranscription(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	apiKey := os.Getenv("TINFOIL_API_KEY")

	c, err := NewClient(context.Background(), option.WithAPIKey(apiKey))
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
