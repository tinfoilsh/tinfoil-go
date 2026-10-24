package tinfoil

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

func TestLiveClientIntegration_TransportModesWithCacheSecret(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	const testUserCacheSecret = "go-live-integration-cache-secret"

	apiKey := os.Getenv("TINFOIL_API_KEY")

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

// TestClientIntegration_LowLevelEHBP exercises the low-level HTTPClient() path
// (direct requests, not the OpenAI wrapper) against a live enclave for both
// transport modes. It covers a bodyless GET, which EHBP sends without body
// encryption per SPEC 7.4, and a POST whose body is sealed end-to-end.
func TestLiveClientIntegration_LowLevelEHBP(t *testing.T) {
	testutil.RequireLive(t, "TINFOIL_API_KEY")
	apiKey := os.Getenv("TINFOIL_API_KEY")

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
