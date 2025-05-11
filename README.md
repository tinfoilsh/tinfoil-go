# Tinfoil Go Client

[![Build Status](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions)

## Installation

`tinfoil-go` currently relies on a specific feature in `go-sev-guest` that hasn't been upstreamed yet. This requires adding the following line to your `go.mod`:

```go
replace github.com/google/go-sev-guest v0.0.0-00010101000000-000000000000 => github.com/jraman567/go-sev-guest v0.0.0-20250117204014-6339110611c9
```

Then run:

```bash
go get github.com/tinfoilsh/tinfoil-go
```

## Quick Start

The Tinfoil Go client is a wrapper around the [OpenAI Go client](https://pkg.go.dev/github.com/openai/openai-go) and provides secure communication with Tinfoil enclaves. It has the same API as the OpenAI client, with additional security features:

- Automatic verification that the endpoint is running in a secure Tinfoil enclave
- TLS certificate pinning to prevent man-in-the-middle attacks
- Attestation validation to ensure enclave integrity

```go
import (
    "fmt"
    "context"
    "github.com/openai/openai-go"
    "github.com/openai/openai-go/option"
    "github.com/tinfoilsh/tinfoil-go" // imported as tinfoil
)

// Create a client for a specific enclave and model repository
client, err := tinfoil.NewClientWithParams("enclave.example.com", "org/model-repo",
    option.WithAPIKey("your-api-key"),
)
if err != nil {
    panic(err.Error())
}

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

## API Documentation

This library is a drop-in replacement for the [official OpenAI Go client](https://github.com/openai/openai-go) that can be used with Tinfoil. All methods and types are identical. See the [OpenAI Go client documentation](https://pkg.go.dev/github.com/openai/openai-go) for complete API usage and documentation.

[![Go Reference](https://pkg.go.dev/badge/github.com/openai/openai-go.svg)](https://pkg.go.dev/github.com/openai/openai-go)


## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to security reports within 24 hours and will keep you updated on our progress.
