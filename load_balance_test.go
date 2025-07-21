package tinfoil

import (
	"context"
	"os"
	"testing"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/stretchr/testify/require"
)

func TestClientLoadBalance(t *testing.T) {
	enclaves := []Enclave{
		{
			Host: "qwen2-5-72b.model.tinfoil.sh",
			Repo: "tinfoilsh/confidential-qwen2-5-72b",
		}, {
			Host: "qwen2-5-72b-2.model.tinfoil.sh",
			Repo: "tinfoilsh/confidential-qwen2-5-72b",
		},
	}

	loadBalancer, err := NewLoadBalancer(enclaves, option.WithAPIKey(os.Getenv("TINFOIL_API_KEY")))
	require.NoError(t, err)

	// Make 4 requests to test load balancing
	for i := 1; i <= 4; i++ {
		t.Logf("Making request #%d", i)

		client := loadBalancer.NextClient()
		chatCompletion, err := client.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.SystemMessage("No matter what the user says, only respond with: Done."),
				openai.UserMessage("Is this a test?"),
			},
			Model: "qwen2-5-72b",
		})
		require.NoError(t, err)

		t.Logf("Request #%d response: %s", i, chatCompletion.Choices[0].Message.Content)
	}
}
