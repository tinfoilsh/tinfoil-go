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

## Verification document

The client retains the result used by its active secure transport:

```go
document := client.VerificationDocument()
fmt.Println(document.ConfigRepo, document.ReleaseTag, document.ReleaseDigest)
fmt.Println(document.Verifier.Name, document.Verifier.Version)
fmt.Println(document.VerifiedAt)
```

`VerifiedAt` is recorded from the local clock after successful verification or
re-verification. It is not an attested timestamp or evidence freshness
guarantee.

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

The inference router partitions prompt-prefix caches using both the authenticated API identity and `user_cache_secret`. Cache reuse requires the same identity, secret, model, and matching prompt prefix. Changing the identity or secret selects a different cache namespace, so those requests do not share cache entries or cache-hit timing.

`user_cache_secret` is sensitive application data used only for cache partitioning. It is not an API credential or encryption key. Do not log or expose it unnecessarily: a caller who can send requests with the same API identity and secret joins that cache namespace and can observe its cache-hit timing. The SDK adds it to eligible request bodies before EHBP sealing or transport over the pinned connection to the verified enclave.

By default, the SDK generates a random secret and persists it at `~/.tinfoil/user_cache_secret`, requesting mode `0600` where supported. Tinfoil SDKs using the same home directory reuse this value. This default is suitable for a single-user application, but it does not separate end users who share one application process or home directory. You can control the scope explicitly:

```go
// Pin a stable, non-empty, opaque secret for this client.
client, err := tinfoil.NewClientWithOptions(
	tinfoil.WithUserCacheSecret(secret),
)

// Or provision it via the environment
//   TINFOIL_USER_CACHE_SECRET=<secret>   use this value

// Multi-user services should scope every request to its end user;
// a non-empty string field set here wins over the client-level secret:
completion, err := client.Chat.Completions.New(ctx, params,
	option.WithJSONSet("user_cache_secret", perUserSecret))
```

Resolution order is a non-empty per-request string, a non-empty client value, a non-empty `TINFOIL_USER_CACHE_SECRET`, then the generated default. Empty client or environment values are treated as unset, and an empty per-request string is replaced with the resolved client value. The SDK leaves non-string values unchanged, and applications should not use them for cache scoping.

Multi-user services must provide a stable, non-empty, opaque value for each user (or group whose members may share cache-hit timing) on every eligible request. Do not use a raw user identifier, API key, or encryption key. A single client, environment, or generated value groups all requests using it under the same API identity. If persistence is unavailable, the SDK uses an in-memory value and cache continuity ends when the process exits.

## API Documentation

This library is a drop-in replacement for the [official OpenAI Go client](https://github.com/openai/openai-go) that can be used with Tinfoil. All methods and types are identical. See the [OpenAI Go client documentation](https://pkg.go.dev/github.com/openai/openai-go/v3) for complete API usage and documentation.

[![Go Reference](https://pkg.go.dev/badge/github.com/openai/openai-go/v3.svg)](https://pkg.go.dev/github.com/openai/openai-go/v3)

## Reporting Vulnerabilities

Please report security vulnerabilities by emailing [security@tinfoil.sh](mailto:security@tinfoil.sh).

We aim to respond to (legitimate) security reports within 24 hours.
