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
    // Skip if no API key is provided; this test performs live network calls
    apiKey := os.Getenv("TINFOIL_API_KEY")
    if apiKey == "" {
        t.Skip("TINFOIL_API_KEY not set; skipping load balancing integration test")
    }

    // Create multiple clients via NewClient and round-robin across them.
    lb, err := NewLoadBalancer(2, option.WithAPIKey(apiKey))
    require.NoError(t, err)

    for i := 1; i <= 4; i++ {
        t.Logf("Making request #%d", i)
        client := lb.NextClient()

        // Use streaming to exercise more of the pipeline.
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
            chunk := stream.Current()
            acc.AddChunk(chunk)
            if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
                t.Logf("Request #%d received: %s", i, chunk.Choices[0].Delta.Content)
            }
        }
        if err := stream.Err(); err != nil {
            t.Fatalf("Request #%d stream error: %v", i, err)
        }
        t.Logf("Request #%d complete response: %s", i, acc.Choices[0].Message.Content)
    }
}
