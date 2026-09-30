package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go"
)

func main() {
	const model = "gpt-oss-120b"
	gateway, err := tinfoil.NewGateway("https://inference-gateway.tinfoil.sh/v1/", nil, tinfoil.GatewayOptions{
		ClientOptions: []tinfoil.ClientOption{tinfoil.WithOpenAIOptions(option.WithAPIKey(os.Getenv("TINFOIL_API_KEY")))},
		ModelPins: map[string]tinfoil.ModelPin{
			model: {Repo: os.Getenv("TINFOIL_MODEL_REF")},
		},
		PinnedModelsOnly: true,
	})
	if err != nil {
		log.Fatal(err)
	}
	completion, err := gateway.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
		Model:    model,
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("Say this is a test")},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(completion.Choices[0].Message.Content)
}
