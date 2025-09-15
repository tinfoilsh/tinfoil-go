# Tinfoil Go Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/go-sdk)

## Installation

Add the Tinfoil SDK to your project:

```bash
go get github.com/tinfoilsh/tinfoil-go
```

`tinfoil-go` currently relies on a specific feature in `go-sev-guest` that hasn't been upstreamed yet. This requires adding the following line to your `go.mod`:

```go
replace github.com/google/go-sev-guest => github.com/tinfoilsh/go-sev-guest v0.0.0-20250704193550-c725e6216008
```

## Quick Start

The Tinfoil Go client is a wrapper around the [OpenAI Go client v2](https://pkg.go.dev/github.com/openai/openai-go/v2) and provides secure communication with Tinfoil enclaves. It has the same API as the OpenAI client, with additional security features:

- Automatic attestation validation to ensure enclave integrity verification
- TLS certificate pinning to prevent man-in-the-middle attacks

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

    "github.com/openai/openai-go/v2"
    "github.com/openai/openai-go/v2/option"
	"github.com/tinfoilsh/tinfoil-go"
)

func main() {
	// Create a client
	client, err := tinfoil.NewClient(
		option.WithAPIKey(os.Getenv("TINFOIL_API_KEY")),
	)
	if err != nil {
		log.Printf("Failed to create client: %v", err)
		return
	}

	// Make requests using the OpenAI client API
	// Note: enclave verification happens automatically
	chatCompletion, err := client.Chat.Completions.New(context.TODO(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage("Say this is a test"),
		},
		Model: "llama3-3-70b", // see https://docs.tinfoil.sh for supported models
	})

	if err != nil {
		log.Printf("Chat completion error: %v", err)
		return
	}

	fmt.Println(chatCompletion.Choices[0].Message.Content)
}
```

## Usage

```go
// 1. Create a client
client, err := tinfoil.NewClient(
	option.WithAPIKey(os.Getenv("TINFOIL_API_KEY")),
)
if err != nil {
	log.Printf("Failed to create client: %v", err)
	return
}

// 2. Use client as you would openai.Client 
// see https://pkg.go.dev/github.com/openai/openai-go/v2 for API documentation
```

## Advanced Functionality

```go
// For manual verification and direct HTTP access, use SecureClient directly
secureClient := tinfoil.NewSecureClient("enclave.example.com", "org/repo")

// Manual verification
groundTruth, err := secureClient.Verify()
if err != nil {
	return fmt.Errorf("verification failed: %w", err)
}

// Get the raw HTTP client 
httpClient, err := secureClient.HTTPClient()
if err != nil {
	return fmt.Errorf("failed to get HTTP client: %w", err)
}

// Make HTTP requests directly 
resp, err := secureClient.Get("/api/status", map[string]string{
	"Authorization": "Bearer token",
})
```

## Foreign Function Interface (FFI) Support

For usage in other languages through FFI, additional functions are available which avoid using FFI incompatible data structures (e.g., Go maps):

```go
// Create a SecureClient for FFI usage
secureClient := tinfoil.NewSecureClient("enclave.example.com", "org/repo")

// Initialize a request and get an ID
requestID, err := secureClient.InitPostRequest("/api/submit", []byte(`{"key":"value"}`))

// Add headers individually
secureClient.AddHeader(requestID, "Content-Type", "application/json")
secureClient.AddHeader(requestID, "Authorization", "Bearer token")

// Execute the request
resp, err := secureClient.ExecuteRequest(requestID)
```

## API Documentation

This library is a drop-in replacement for the [official OpenAI Go client](https://github.com/openai/openai-go) that can be used with Tinfoil. All methods and types are identical. See the [OpenAI Go client documentation](https://pkg.go.dev/github.com/openai/openai-go/v2) for complete API usage and documentation.

[![Go Reference](https://pkg.go.dev/badge/github.com/openai/openai-go/v2.svg)](https://pkg.go.dev/github.com/openai/openai-go/v2)

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.
