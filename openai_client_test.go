package tinfoil

import (
	"context"
	"os"
	"testing"

	"github.com/openai/openai-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: All tests only pass when provided with a valid enclave and repo
type testConfig struct {
	enclave string
	repo    string
}

var testCfg testConfig

func TestMain(m *testing.M) {
	// Load config from environment with defaults
	testCfg = testConfig{
		enclave: getEnvOrDefault("TINFOIL_TEST_ENCLAVE", "models.default.tinfoil.sh"),
		repo:    getEnvOrDefault("TINFOIL_TEST_REPO", "tinfoilsh/default-models-nitro"),
	}

	code := m.Run()
	os.Exit(code)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func TestNewClient(t *testing.T) {
	// Test environment variable based client creation
	client, err := NewClient()
	require.NoError(t, err)
	require.NotNil(t, client)

	// Test explicit client creation
	clientExplicit, err := NewClientWithParams(testCfg.enclave, testCfg.repo)
	require.NoError(t, err)
	require.NotNil(t, clientExplicit)

	// Verify client properties
	assert.Equal(t, testCfg.enclave, clientExplicit.enclave)
	assert.Equal(t, testCfg.repo, clientExplicit.repo)
	assert.NotNil(t, clientExplicit.groundTruth)
	assert.NotNil(t, clientExplicit.Client)
}

// TestClientIntegration_Chat tests the chat completion with specified parameters
func TestClientIntegration_Chat(t *testing.T) {
	client, err := NewClientWithParams(testCfg.enclave, testCfg.repo)
	require.NoError(t, err)

	// Using the exact parameters provided
	chatCompletion, err := client.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Messages: openai.F([]openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("You are a helpful assistant."),
			openai.UserMessage("Why is tinfoil now called aluminum foil?"),
		}),
		Model: openai.F("llama3.2:1b"),
	})
	require.NoError(t, err)

	t.Logf("Response received: %s", chatCompletion.Choices[0].Message.Content)
}

// TestClientNonStreamingChat tests the non-streaming version with the same parameters
func TestClientNonStreamingChat(t *testing.T) {
	client, err := NewClientWithParams(testCfg.enclave, testCfg.repo)
	require.NoError(t, err)

	// Same parameters but without streaming
	resp, err := client.Chat.Completions.New(
		context.Background(),
		openai.ChatCompletionNewParams{
			Model: openai.F("llama3.2:1b"),
			Messages: openai.F([]openai.ChatCompletionMessageParamUnion{
				openai.SystemMessage("You are a helpful assistant."),
				openai.UserMessage("Why is tinfoil now called aluminum foil?"),
			}),
		},
	)

	if err != nil {
		t.Logf("Chat request completed with error: %v", err)
	} else {
		t.Logf("Response received: %s", resp.Choices[0].Message.Content)
	}
}

// TestClientStreamingChat tests the streaming version with the same parameters
func TestClientStreamingChat(t *testing.T) {
	client, err := NewClientWithParams(testCfg.enclave, testCfg.repo)
	require.NoError(t, err)

	// Create a streaming chat completion request
	stream := client.Chat.Completions.NewStreaming(context.Background(), openai.ChatCompletionNewParams{
		Messages: openai.F([]openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage("You are a helpful assistant."),
			openai.UserMessage("Why is tinfoil now called aluminum foil?"),
		}),
		Model: openai.F("llama3.2:1b"),
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
