# Tinfoil Go Client

[![SDK Tests](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml)
[![govulncheck](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/govulncheck.yml)
[![Documentation](https://img.shields.io/badge/docs-tinfoil.sh-blue)](https://docs.tinfoil.sh/sdk/go-sdk)

A Go client for verifiably private AI inference with Tinfoil. It wraps the [OpenAI Go client v3](https://pkg.go.dev/github.com/openai/openai-go/v3) with the same API, and before sending any request it verifies the enclave's attestation. The enclave and router clients then pin the TLS connection to the attested key, so only the verified enclave can read the request, headers included. To send their requests through your own proxy, set the `Transport` option to `tinfoil.EHBP{ProxyURL: ...}`, which encrypts request and response bodies to the attested key using [EHBP](https://docs.tinfoil.sh/resources/ehbp) but leaves the method, URL and headers visible to the proxy. The gateway clients always use EHBP, so Tinfoil's gateway sees the method, URL and headers of their requests.

## Installation

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
- Multi-user services must scope prompt caches to each end user with a per-request `user_cache_secret`, or `UserCacheSecret` in the router or gateway client's options; see [Prompt caching](https://docs.tinfoil.sh/sdk/prompt-caching). The enclave client never adds or changes `user_cache_secret`, so a caller that points it at Tinfoil's router sets the field in each request body, for example with `option.WithJSONSet("user_cache_secret", s)`.
- `tinfoil.NewEnclaveHTTPClient` returns a client for one enclave that embeds an `*http.Client` for requests to it; `tinfoil.NewGatewayHTTPClient` returns one that seals each request to a verified replica of its model through Tinfoil's gateway. The gateway constructors are experimental and may change in a later release. Each checks its configuration before it returns, so a misconfigured client fails at construction: the enclave client verifies its enclave, and the gateway client fetches its catalog and verifies each model's replicas on first use. `tinfoil.NewRouterHTTPClient` discovers and verifies Tinfoil's router the same way, and returns a `RouterHTTPClient` configured by `RouterOptions`. All three take a [`verify.Policy`](verify/README.md#verification-options) in their options to pin registers or set freshness, a `VerificationCheck` that can reject a verified enclave by its `verify.VerifiedFacts`, and an `OnVerification` callback that sees every verification attempt. `tinfoil.NewOpenAIClient(httpClient, opts, openaiOpts...)` builds an OpenAI client on top of any of the three, without further network I/O. Its base URL is `OpenAIOptions.APIPath` (`/v1/` by default) under the proxy URL or the enclave's origin, or the gateway's `URL` as given. The SDK sets the base URL after the OpenAI options, so an `option.WithBaseURL` has no effect; set `APIPath` to change the path, or, for a gateway client, which takes no `APIPath`, the gateway's `URL`.
- The enclave clients take a required `tinfoil.Trust` that names who vouches for the enclave's config: `RepoPin` (a GitHub repository, v2 collateral), `ProjectPin` (a config registry project, v3 collateral), `SignedBy` (your own config signing keys), `AuthorizedBy` (a callback that approves each config), `EmbeddedConfig` (the exact config bytes) or `EitherPin` (a repository and a project, both required, that accepts v2 collateral for the repository or v3 collateral for the project, for the move from v2 to v3 collateral):

  ```go
  client, err := tinfoil.NewEnclaveHTTPClient(ctx, "inference.tinfoil.sh",
      tinfoil.ProjectPin{Project: "tinfoilsh/confidential-model-router"},
      &tinfoil.EnclaveOptions{Policy: verify.Policy{FreshnessMaxAge: 24 * time.Hour}})
  ```

  A `ProjectPin` with nil `RegistryIDs` trusts Tinfoil's public registry; a non-empty list trusts exactly the registries that it names, and an empty but non-nil list is an `ErrConfiguration` error.
- Every verification produces a `verify.VerificationReport` that lists the four verification steps (envelope, provenance, quote and policy) and what each one established. The enclave and router clients' `EnsureVerified` and `Reverify` return it, and `LastVerification()` returns the most recent attempt without I/O: its report, or the error that the client reported for it. When the verifier rejects a document, the client's `ErrAttestation` error wraps a `*verify.VerificationError` whose `Report` shows the step that failed, next to what the earlier steps established:

  ```go
  _, err := client.EnsureVerified(ctx)
  var rejected *verify.VerificationError
  if errors.As(err, &rejected) {
      for _, step := range rejected.Report.Steps {
          fmt.Println(step.Layer, step.Status, step.Message)
      }
  }
  ```

  `OnVerification(host, report, err)` is called once for every attempt, including retries, re-verification after a key rotation and each router that discovery tries, and is a way to show verification status as it happens. The gateway client's `LastVerification()` returns each replica's last attempt. An attempt that fails before the verifier runs, such as a fetch that fails with an `ErrNetwork` error, has no report. Channel keys come only from a report's `VerifiedFacts`; a failed report holds key fingerprints only, which are unverified.
- All OpenAI methods and types are unchanged; see the [OpenAI Go client documentation](https://pkg.go.dev/github.com/openai/openai-go/v3).

## Reaching Only Your Own Origin

By default, a client fetches attestation documents directly from enclaves, and the router client fetches its candidate routers from `https://atc.tinfoil.sh/routers`. To have a client reach only your own origin, for example under a strict content security policy in a browser, or so that enclaves never see your users' IP addresses, serve three endpoints under one URL and point the client at them:

```go
const origin = "https://app.example/tinfoil"
client, err := tinfoil.NewRouterHTTPClient(ctx, &tinfoil.RouterOptions{
    Transport:        tinfoil.EHBP{ProxyURL: origin},
    FetchAttestation: tinfoil.AttestationRelay{URL: origin},
    FetchRouterList:  tinfoil.RouterListRelay{URL: origin},
})
```

| The client sends | Your server forwards it to |
|---|---|
| `GET {URL}/.well-known/tinfoil-attestation?nonce={hex}&enclave={host}` | `GET https://{host}/.well-known/tinfoil-attestation?nonce={hex}`, returning the body unchanged |
| `GET {URL}/routers` | `GET https://atc.tinfoil.sh/routers`, returning the body unchanged |
| Any other request under `{URL}`, such as `{URL}/v1/chat/completions` | The enclave that its `X-Tinfoil-Enclave-Url` header names, at the path that follows `{URL}` |

Each option also works alone, and `EnclaveOptions` takes `FetchAttestation` too. For anything else, such as your own transport, pass an `AttestationFetcherFunc` or a `RouterListFetcherFunc`. The client verifies every document as it verifies one that it fetched itself, so the relays can make verification fail but can't make an enclave pass. Two things remain trusted: the router list, because an attestation document doesn't name the host that serves it, so with EHBP a host that the list names receives the request headers, including the API key, although not the bodies; and your server, which sees those headers anyway. Forward attestation requests only to enclave hosts that you expect, so that the relay isn't an open proxy.

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
