# Tinfoil Go Client

[![SDK Tests](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml)
[![govulncheck](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/govulncheck.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/go-sdk)

A Go client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Go client v3](https://pkg.go.dev/github.com/openai/openai-go/v3) with the same API, and before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it. A TLS certificate pinning transport is available as a fallback.

For complete documentation, see the [Go SDK documentation](https://docs.tinfoil.sh/sdk/go-sdk).

## Installation

Requires Go 1.27.1 or later.

```bash
go get github.com/tinfoilsh/tinfoil-go
```

## Quick Start

```go
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
	client, err := tinfoil.NewClient(
		option.WithAPIKey(os.Getenv("TINFOIL_API_KEY")),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Enclave verification and encryption happen automatically.
	chatCompletion, err := client.Chat.Completions.New(context.TODO(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage("Say this is a test"),
		},
		Model: "llama3-3-70b", // see https://docs.tinfoil.sh/models/catalog
	})
	if err != nil {
		log.Fatalf("Chat completion error: %v", err)
	}

	fmt.Println(chatCompletion.Choices[0].Message.Content)
}
```

## Verification document

The client retains the result used by its active secure transport:

```go
document := client.Verification()
fmt.Println(document.ConfigRepo, document.CodeTag, document.CodeDigest)
fmt.Println(document.Verifier.Name, document.Verifier.Version)
fmt.Println(document.VerifiedAt)
```

`VerifiedAt` is recorded from the local clock after successful verification. It is not an attested timestamp or a freshness guarantee.

## Prompt Cache Scoping

The router partitions prompt caches by API identity and a `user_cache_secret` that the SDK adds to eligible requests. By default it generates one and persists it at `~/.tinfoil/user_cache_secret`, which is suitable for single-user applications. Multi-user services should scope each request to its end user:

```go
// Pin a stable, opaque secret for this client (or set TINFOIL_USER_CACHE_SECRET).
client, err := tinfoil.NewClientWithOptions(
	tinfoil.WithUserCacheSecret(secret),
)

// A per-request value wins over the client-level secret.
completion, err := client.Chat.Completions.New(ctx, params,
	option.WithJSONSet("user_cache_secret", perUserSecret))
```

See [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching) for resolution order and guidance on choosing a scope.

## Advanced Functionality

```go
// Target a specific enclave and repository
client, err := tinfoil.NewClientWithOptions(tinfoil.WithEnclave(enclave), tinfoil.WithRepo(repo))

// Make verified HTTP requests to the enclave directly
httpClient := client.HTTPClient()
resp, err := httpClient.Get(fmt.Sprintf("https://%s/health", enclave))
```

`WithVerificationOptions` configures [register pins and freshness](verifier/README.md#verification-options).

## Error handling

Use `errors.As` to distinguish SDK failures:

```go
var config *tinfoil.ConfigurationError
var fetch *tinfoil.FetchError
var attestation *tinfoil.AttestationError
switch {
case errors.As(err, &config):
	// Invalid arguments or client configuration.
case errors.As(err, &fetch):
	// Attestation material could not be fetched; retry may help.
case errors.As(err, &attestation):
	// Verification or channel binding failed; do not trust this result.
}
```

All three implement `tinfoil.Error`. Upstream OpenAI errors pass through unchanged. Let `SecureClient` own key-rotation recovery rather than retrying every `AttestationError` in application code.

## API Documentation

This library is a drop-in replacement for the [official OpenAI Go client](https://github.com/openai/openai-go). All methods and types are identical; see the [OpenAI Go client documentation](https://pkg.go.dev/github.com/openai/openai-go/v3) for API usage.

## Development

Run `go test -race ./...` for local tests. Live tests require explicit opt-in: set `TINFOIL_API_KEY`, `TINFOIL_ENCLAVE`, and `TINFOIL_REPO`, then run:

```sh
RUN_TINFOIL_INTEGRATION=true go test -race -count=1 -timeout 5m -run '^TestLive' ./...
```

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)
- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
