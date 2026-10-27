package transport

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

const (
	enclaveEnvVar = "TINFOIL_ENCLAVE"
	repoEnvVar    = "TINFOIL_REPO"
	apiKeyEnvVar  = "TINFOIL_API_KEY"
)

// ChatCompletionRequest represents a chat completion request
type ChatCompletionRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionResponse represents a chat completion response
type ChatCompletionResponse struct {
	Choices []Choice `json:"choices"`
}

// Choice represents a choice in the chat completion response
type Choice struct {
	Message Message `json:"message"`
}

func TestLiveBasicChatCompletion(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar, apiKeyEnvVar)
	host, repo, apiKey := os.Getenv(enclaveEnvVar), os.Getenv(repoEnvVar), os.Getenv(apiKeyEnvVar)

	// Create the enclave handle
	client, err := enclave.NewHandle(enclave.Config{Host: host, Repo: repo})
	require.NoError(t, err)

	// Prepare chat completion request
	request := ChatCompletionRequest{
		Model: "gpt-oss-120b",
		Messages: []Message{
			{
				Role:    "user",
				Content: "Hi",
			},
		},
	}

	requestBody, err := json.Marshal(request)
	require.NoError(t, err)

	// Make the request over the pinned TLS client
	hc := tlsClient(client)
	req, err := http.NewRequest(http.MethodPost, "https://"+host+"/v1/chat/completions", bytes.NewReader(requestBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := hc.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode, "Expected successful response, got: %s", string(body))

	// Parse response
	var chatResponse ChatCompletionResponse
	err = json.Unmarshal(body, &chatResponse)
	require.NoError(t, err)

	// Verify response contains non-empty content
	require.NotEmpty(t, chatResponse.Choices, "Response should contain at least one choice")
	assert.NotEmpty(t, chatResponse.Choices[0].Message.Content, "Response content should not be empty")

	// Log the response content (like the Python test does)
	t.Logf("Response content: %s", chatResponse.Choices[0].Message.Content)
}
