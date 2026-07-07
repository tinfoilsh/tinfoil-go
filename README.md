# Tinfoil Go Client

[![SDK Tests](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml)
[![govulncheck](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/govulncheck.yml)

[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/go-sdk)

For complete documentation, see the [Go SDK documentation](https://docs.tinfoil.sh/sdk/go-sdk).

## Installation

Add the Tinfoil SDK to your project:

```bash
go get github.com/tinfoilsh/tinfoil-go
```

## Quick Start

The Tinfoil Go client is a wrapper around the [OpenAI Go client v3](https://pkg.go.dev/github.com/openai/openai-go/v3) and provides secure communication with Tinfoil enclaves. It has the same API as the OpenAI client, with additional security features:

- Automatic attestation validation to ensure enclave integrity verification
- Supports [Encrypted HTTP Body Protocol](https://docs.tinfoil.sh/resources/ehbp) to provide direct-to-enclave encrypted communication with attested public keys
- Supports a fallback mode with TLS certificate pinning using attested certificates to provide direct-to-enclave encrypted communication over TLS 

```go
package main

import (
	"context"
	"fmt"
	"log"

    "github.com/openai/openai-go/v3"
    "github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go"
)

func main() {
	// Create a client
	client, err := tinfoil.NewClient(
		option.WithAPIKey("<YOUR_API_KEY>"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Make requests using the OpenAI client API
	// Note: enclave verification and direct-to-enclave encryption happens automatically
	chatCompletion, err := client.Chat.Completions.New(context.TODO(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage("Say this is a test"),
		},
		Model: "llama3-3-70b", // see https://docs.tinfoil.sh/models/catalog for supported models
	})

	if err != nil {
		log.Fatalf("Chat completion error: %v", err)
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
// see https://pkg.go.dev/github.com/openai/openai-go/v3 for API documentation
```

## Advanced Functionality

```go
// Create a secure client with explicit enclave and repo parameters
client, err := tinfoil.NewClientWithParams(enclave, repo)
if err != nil {
	return fmt.Errorf("Failed to create client: %v", err)
}

// For direct HTTP access, use the underlying HTTPClient
httpClient := client.HTTPClient()
endpoint := fmt.Sprintf("https://%s/health", enclave)
resp, err := httpClient.Get(endpoint)
if err != nil {
	return fmt.Errorf("Request failed: %v", err)
}
```

## Prompt Cache Scoping

The inference router partitions its prompt cache per API identity, so your cached prompts are never observable by other tenants. Within your tenant, the SDK scopes caching further with a `user_cache_secret`: requests carrying the same secret share cached prompt prefixes, requests carrying different secrets cannot observe each other's cache timing. The secret never reaches the model — the router consumes it to derive the cache namespace and strips it from the request.

By default the SDK generates a random secret and persists it at `~/.tinfoil/user_cache_secret` (mode `0600`, shared with the other Tinfoil SDKs on the same machine), so caching just works with per-machine scoping. You can control it explicitly:

```go
// Pin the secret for this client (e.g. one stable value per end user)
client, err := tinfoil.NewClientWithOptions(
	tinfoil.WithUserCacheSecret(secret),
)

// Or provision it via the environment
//   TINFOIL_USER_CACHE_SECRET=<secret>   use this value
//   TINFOIL_USER_CACHE_SECRET=           (set but empty) disable: tenant-wide caching

// Servers that hold many end users' conversations should scope per request;
// a field set here always wins over the client-level secret:
completion, err := client.Chat.Completions.New(ctx, params,
	option.WithJSONSet("user_cache_secret", perUserSecret))

// Opt out entirely (tenant-wide caching, no file written)
client, err = tinfoil.NewClientWithOptions(tinfoil.WithUserCacheSecret(""))
```

If the secret cannot be persisted (no home directory, read-only filesystem), the SDK falls back to an in-memory secret and warns once: cache continuity then resets on every process restart. Containerized deployments should set `TINFOIL_USER_CACHE_SECRET` explicitly — one value per end user if requests are per-user, or empty to keep tenant-wide caching across replicas.

## API Documentation

This library is a drop-in replacement for the [official OpenAI Go client](https://github.com/openai/openai-go) that can be used with Tinfoil. All methods and types are identical. See the [OpenAI Go client documentation](https://pkg.go.dev/github.com/openai/openai-go/v3) for complete API usage and documentation.

[![Go Reference](https://pkg.go.dev/badge/github.com/openai/openai-go/v3.svg)](https://pkg.go.dev/github.com/openai/openai-go/v3)

## Reporting Vulnerabilities

Please report security vulnerabilities by emailing [security@tinfoil.sh](mailto:security@tinfoil.sh).

We aim to respond to (legitimate) security reports within 24 hours.
