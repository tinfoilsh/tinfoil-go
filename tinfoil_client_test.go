package tinfoil

import (
    "context"
    "os"
    "testing"

    "github.com/openai/openai-go"
    "github.com/openai/openai-go/option"
    "github.com/stretchr/testify/require"
)

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
    for stream.Next() {
        chunk := stream.Current()
        acc.AddChunk(chunk)

		if content, ok := acc.JustFinishedContent(); ok {
			t.Logf("Content stream finished: %s", content)
		}

		// it's best to use chunks after handling JustFinished events
        if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
            t.Logf("Received: %s", chunk.Choices[0].Delta.Content)
        }
    }

    if err := stream.Err(); err != nil {
        t.Fatalf("Stream error: %v", err)
    }

	// After the stream is finished, acc can be used like a ChatCompletion
	t.Logf("Complete response: %s", acc.Choices[0].Message.Content)
}
