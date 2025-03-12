# Tinfoil Go Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions)

## Installation

```bash
go get github.com/tinfoilsh/tinfoil-go
```

## Quick Start: Use the Tinfoil Go client 

The Tinfoil Go client is a wrapper around the [OpenAI Go client](https://pkg.go.dev/github.com/openai/openai-go) and provides secure communication with Tinfoil enclaves. It has the same API as the OpenAI client, with additional security features:

- Automatic verification that the endpoint is running in a secure Tinfoil enclave
- TLS certificate pinning to prevent man-in-the-middle attacks
- Attestation validation to ensure enclave integrity

```go
import (
    "fmt"
    "github.com/tinfoilsh/tinfoil-go" // imported as tinfoil
)

// Create a client for a specific enclave and model repository
client := tinfoil.NewSecureClient("enclave.example.com", "org/model-repo")

// Make requests using the OpenAI client API
// Note: enclave verification happens automatically
chatCompletion, err := client.Chat.Completions.New(context.TODO(), openai.ChatCompletionNewParams{
    Messages: openai.F([]openai.ChatCompletionMessageParamUnion{
        openai.UserMessage("Say this is a test"),
    }),
    Model: openai.F("llama3.2:1b"), // see https://docs.tinfoil.sh for supported models
})

if err != nil {
    panic(err.Error())
}

fmt.Println(chatCompletion.Choices[0].Message.Content)
```

### Usage

```go
// 1. Create a client
client := tinfoil.NewSecureClient(
    "enclave.example.com",  // Enclave hostname
    "org/repo",            // GitHub repository
)

// 2. Use client as you would openai.Client 
// see https://pkg.go.dev/github.com/openai/openai-go for API documentation
```

### Advanced functionality

```go
// Manual verification
state, err := client.Verify()
if err != nil {
    return fmt.Errorf("verification failed: %w", err)
}

// Get the raw HTTP client 
httpClient, err := client.HTTPClient()
if err != nil {
    return fmt.Errorf("failed to get HTTP client: %w", err)
}

// Make HTTP requests directly 
resp, err := client.Get("/api/status", map[string]string{
    "Authorization": "Bearer token",
})
```

### Foreign Function Interface (FFI) Support

For usage in other languages through FFI, additional functions are available 
which avoid using FFI incompatible data structures (e.g., Go maps): 

```go
// Initialize a request and get an ID
requestID, err := client.InitPostRequest("/api/submit", []byte(`{"key":"value"}`))

// Add headers individually
client.AddHeader(requestID, "Content-Type", "application/json")
client.AddHeader(requestID, "Authorization", "Bearer token")

// Execute the request
resp, err := client.ExecuteRequest(requestID)
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.
