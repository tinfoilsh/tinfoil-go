package tinfoil

import (
	"context"
	"testing"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	// Test default client creation
	client, err := NewClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	// Test explicit client creation with custom parameters
	customEnclave := "llama3-3-70b.model.tinfoil.sh"
	customRepo := "tinfoilsh/confidential-llama3-3-70b"

	clientExplicit, err := NewClientWithParams(customEnclave, customRepo)
	require.NoError(t, err)
	require.NotNil(t, clientExplicit)

	// Verify client properties
	assert.Equal(t, customEnclave, clientExplicit.enclave)
	assert.Equal(t, customRepo, clientExplicit.repo)
	assert.NotNil(t, clientExplicit.Client)
}

// TestClientIntegration_Chat tests the chat completion with default parameters
func TestClientIntegration_Chat(t *testing.T) {
	client, err := NewClient(option.WithAPIKey("<YOUR_API_KEY>"))
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
	client, err := NewClient(option.WithAPIKey("<YOUR_API_KEY>"))
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
	client, err := NewClient(option.WithAPIKey("<YOUR_API_KEY>"))
	require.NoError(t, err)

	// Create a streaming chat completion request
	stream := client.Chat.Completions.NewStreaming(context.Background(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("No matter what the user says, only respond with: Done."),
			openai.UserMessage("Is this a test?"),
		},
		Model: "llama3-3-70b",
	})

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

// TestClientWithCustomParams tests using custom enclave and repo parameters
func TestClientWithCustomParams(t *testing.T) {
	customEnclave := "llama3-3-70b.model.tinfoil.sh"
	customRepo := "tinfoilsh/confidential-llama3-3-70b"

	client, err := NewClientWithParams(
		customEnclave,
		customRepo,
		option.WithAPIKey("<YOUR_API_KEY>"),
	)
	require.NoError(t, err)

	// Verify the custom parameters are set correctly
	assert.Equal(t, customEnclave, client.enclave)
	assert.Equal(t, customRepo, client.repo)
	assert.NotNil(t, client.Client)
}
