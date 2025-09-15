package tinfoil

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
	"github.com/stretchr/testify/require"
	"github.com/subosito/gotenv"
)

// Load .env before running tests so TINFOIL_API_KEY is available locally
func TestMain(m *testing.M) {
	// Ignore error: if .env is missing, we just proceed
	_ = gotenv.Load()
	os.Exit(m.Run())
}

func TestNewClient(t *testing.T) {
	// Test default client creation only
	client, err := NewClient()
	require.NoError(t, err)
	require.NotNil(t, client)
}

// TestClientIntegration_Chat tests the chat completion with default parameters
func TestClientIntegration_Chat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	client, err := NewClient(option.WithAPIKey(apiKey))
	require.NoError(t, err)

	chatCompletion, err := client.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
		Model: "llama3-3-70b",
	})
	require.NoError(t, err)

	t.Logf("Response received: %s", chatCompletion.Choices[0].Message.Content)
}

// TestClientNonStreamingChat tests the non-streaming version with default parameters
func TestClientNonStreamingChat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	client, err := NewClient(option.WithAPIKey(apiKey))
	require.NoError(t, err)

	resp, err := client.Chat.Completions.New(
		context.Background(),
		openai.ChatCompletionNewParams{
			Model: "llama3-3-70b",
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.SystemMessage("No matter what the user says, only respond with: Done."),
				openai.UserMessage("Is this a test?"),
			},
		},
	)

	if err != nil {
		t.Logf("Chat request completed with error: %v", err)
	} else {
		t.Logf("Response received: %s", resp.Choices[0].Message.Content)
	}
}

// TestClientStreamingChat tests the streaming version with default parameters
func TestClientStreamingChat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	client, err := NewClient(option.WithAPIKey(apiKey))
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

	// optionally, an accumulator helper can be used
	acc := openai.ChatCompletionAccumulator{}

	t.Log("Chat completion streaming response:")
	sawAnyContent := false
	for stream.Next() {
		chunk := stream.Current()
		acc.AddChunk(chunk)

		if content, ok := acc.JustFinishedContent(); ok {
			t.Logf("Content stream finished: %s", content)
		}

		// it's best to use chunks after handling JustFinished events
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			t.Logf("Received: %s", chunk.Choices[0].Delta.Content)
			sawAnyContent = true
		}
	}

	// The backend currently emits an extra blank line before the final
	// "data: [DONE]" SSE event. openai-go's SSE decoder treats each blank
	// line as a separate event and attempts to JSON-decode the empty event,
	// yielding "unexpected end of JSON input". Since we received content and
	// the stream otherwise completed, treat that specific error as a benign
	// termination until the backend is fixed.
	if err := stream.Err(); err != nil {
		if sawAnyContent && strings.Contains(err.Error(), "unexpected end of JSON input") {
			t.Logf("Ignoring benign end-of-stream parse error: %v", err)
		} else {
			t.Fatalf("Stream error: %v", err)
		}
	}

	// After the stream is finished, acc can be used like a ChatCompletion
	t.Logf("Complete response: %s", acc.Choices[0].Message.Content)
}

// TestDirectClientStreamingChat compares streaming using the raw OpenAI client
// (no Tinfoil HTTP transport) against the wrapped client to isolate the source
// of any streaming errors. If this test passes while TestClientStreamingChat
// fails, the issue likely lies in the Secure HTTP client/transport.
func TestDirectClientStreamingChat(t *testing.T) {
	apiKey := os.Getenv("TINFOIL_API_KEY")
	if apiKey == "" {
		t.Skip("TINFOIL_API_KEY not set; skipping integration test")
	}

	// Build a plain OpenAI client pointing at the Tinfoil inference endpoint
	// without using the SecureClient's HTTP transport. This helps determine
	// whether streaming issues come from our wrapper or from the endpoint/API.
	raw := openai.NewClient(
		option.WithAPIKey(apiKey),
		option.WithBaseURL("https://inference.tinfoil.sh/v1"),
	)

	stream := raw.Chat.Completions.NewStreaming(context.Background(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
		Model: "llama3-3-70b",
	})
	defer stream.Close()

	acc := openai.ChatCompletionAccumulator{}
	t.Log("Direct client streaming response:")
	sawAnyContent := false
	for stream.Next() {
		chunk := stream.Current()
		acc.AddChunk(chunk)
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			t.Logf("Received: %s", chunk.Choices[0].Delta.Content)
			sawAnyContent = true
		}
	}

	// See comment above in TestClientStreamingChat.
	if err := stream.Err(); err != nil {
		if sawAnyContent && strings.Contains(err.Error(), "unexpected end of JSON input") {
			t.Logf("Ignoring benign end-of-stream parse error: %v", err)
		} else {
			t.Fatalf("Direct stream error: %v", err)
		}
	}

	t.Logf("Direct complete response: %s", acc.Choices[0].Message.Content)
}
