# Tinfoil Go Client

[![SDK Tests](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml)
[![govulncheck](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/govulncheck.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/go-sdk)

A Go client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Go client v3](https://pkg.go.dev/github.com/openai/openai-go/v3) with the same API, and before sending any request it verifies the enclave's attestation and encrypts the request body to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp), so only the verified enclave can read it. TLS certificate pinning is available as a fallback through `EnclaveOptions.TransportMode`.

## Installation

Requires Go 1.27.3 or later.

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
	client, err := tinfoil.NewClient(context.Background(),
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
		Model: "gpt-oss-120b", // see https://docs.tinfoil.sh/models/chat
	})
	if err != nil {
		log.Fatalf("Chat completion error: %v", err)
	}

	fmt.Println(chatCompletion.Choices[0].Message.Content)
}
```

## Documentation

- [Go SDK documentation](https://docs.tinfoil.sh/sdk/go-sdk) and [error handling](https://docs.tinfoil.sh/sdk/error-handling).
- Multi-user services must scope prompt caches to each end user with a per-request `user_cache_secret`, or `UserCacheSecret` in a client's options; see [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching).
- `tinfoil.NewEnclaveHTTPClient` returns a client for one enclave that embeds an `*http.Client` for requests to it; `tinfoil.NewGatewayHTTPClient` returns one that seals each request to a verified replica of its model through Tinfoil's gateway. Each checks its configuration before it returns, so a misconfigured client fails at construction: the enclave client verifies its enclave, and the gateway client fetches its catalog and verifies each model's replicas on first use. `tinfoil.NewRouterHTTPClient` verifies Tinfoil's router the same way. All three take a [`verify.Verifier`](verify/README.md) in their options to pin registers or set freshness, and a `VerificationCheck` that can reject a verified enclave by its `verify.Verification`. The matching `OpenAIClient` constructors take the same options plus OpenAI options, and return an OpenAI client that sends through one of them.
- All OpenAI methods and types are unchanged; see the [OpenAI Go client documentation](https://pkg.go.dev/github.com/openai/openai-go/v3).

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
