# Tinfoil Go Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions)

## Installation

`tinfoil-go` currently relies on a specific feature in `go-sev-guest` that hasn't been upstreamed yet:

```go
go mod edit -replace github.com/google/go-sev-guest=github.com/tinfoilsh/go-sev-guest@v0.0.0-20250704193550-c725e6216008
```

Then run:

```bash
go get github.com/tinfoilsh/tinfoil-go
```

## Quick Start

The Tinfoil Go client is a wrapper around the [OpenAI Go client](https://pkg.go.dev/github.com/openai/openai-go) and provides secure communication with Tinfoil enclaves. It has the same API as the OpenAI client, with additional security features:

- Automatic attestation validation to ensure enclave integrity verification
- TLS certificate pinning to prevent man-in-the-middle attacks

```go
package main

import (
	"context"
	"fmt"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/tinfoilsh/tinfoil-go" // imported as tinfoil
)

func main() {
	// Create a client for a specific enclave and model repository
	client, err := tinfoil.NewClientWithParams(
		"enclave.example.com",
		"org/model-repo",
		option.WithAPIKey("your-api-key"),
	)
	if err != nil {
		panic(err.Error())
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
		panic(err.Error())
	}

	fmt.Println(chatCompletion.Choices[0].Message.Content)
}
```

## Usage

```go
// 1. Create a client
client, err := tinfoil.NewClientWithParams(
	"enclave.example.com",  // Enclave hostname
	"org/repo",             // GitHub repository
	option.WithAPIKey("your-api-key"),
)
if err != nil {
	panic(err.Error())
}

// 2. Use client as you would openai.Client 
// see https://pkg.go.dev/github.com/openai/openai-go for API documentation
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

This library is a drop-in replacement for the [official OpenAI Go client](https://github.com/openai/openai-go) that can be used with Tinfoil. All methods and types are identical. See the [OpenAI Go client documentation](https://pkg.go.dev/github.com/openai/openai-go) for complete API usage and documentation.

[![Go Reference](https://pkg.go.dev/badge/github.com/openai/openai-go.svg)](https://pkg.go.dev/github.com/openai/openai-go)

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.
