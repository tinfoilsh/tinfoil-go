package main

import (
	"context"
	"fmt"
	"log"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/sirupsen/logrus"
	"github.com/tinfoilsh/tinfoil-go"
)

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	// Create a new tinfoil client
	client, err := tinfoil.NewClientWithParams(
		"llama3-3-70b.model.tinfoil.sh",
		"tinfoilsh/confidential-llama3-3-70b",
		option.WithAPIKey("tinfoil"), // Replace with your actual API key
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Streaming chat completion
	fmt.Println("\n=== Streaming Chat Completion ===")

	systemPrompt := "You are a helpful assistant."
	userPrompt := "Tell me a short story about aluminum foil."

	fmt.Printf("System: %s\n", systemPrompt)
	fmt.Printf("User: %s\n\n", userPrompt)

	stream := client.Chat.Completions.NewStreaming(
		context.Background(),
		openai.ChatCompletionNewParams{
			Model: "llama3-3-70b",
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.SystemMessage(systemPrompt),
				openai.UserMessage(userPrompt),
			},
		},
	)

	fmt.Println("Assistant:")
	// Use the accumulator to collect the full response
	acc := openai.ChatCompletionAccumulator{}

	fmt.Println("Streaming response:")
	for stream.Next() {
		chunk := stream.Current()
		acc.AddChunk(chunk)

		// Print content as it arrives
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			fmt.Print(chunk.Choices[0].Delta.Content)
		}
	}

	if err := stream.Err(); err != nil {
		log.Fatalf("Stream error: %v", err)
	}

	fmt.Println("\n\nFull accumulated response:")
	fmt.Println(acc.Choices[0].Message.Content)
}
