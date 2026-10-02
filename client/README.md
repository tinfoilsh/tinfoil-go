# Tinfoil Secure Client

Secure HTTP client for enclave-backed services.

## Overview
`client.SecureClient` fetches an enclave's attestation document, verifies it
with the [verifier](../verify/README.md), and binds HTTP traffic to the
attested keys. Fetching, caching, expiry and retries live here; the verifier
itself performs no I/O.

## Features
- **Secure HTTP client** with automatic TLS certificate pinning

## Installation
```bash
go get github.com/tinfoilsh/tinfoil-go@latest
```

## Quick Start
```go
import "github.com/tinfoilsh/tinfoil-go/client"

// 1. Create a client
tinfoilClient, err := client.NewSecureClient("enclave.example.com", "org/repo", nil)
if err != nil { log.Fatal(err) }

// 2. Perform HTTP requests – attestation happens automatically
resp, err := tinfoilClient.Request("GET", "/api/data", "", nil)
if err != nil {
    log.Fatal(err)
}
log.Printf("Status: %s, Body: %s", resp.Status, string(resp.Body))
```

To verify manually and expose the verification state:
```go
verified, err := tinfoilClient.Verify()
if err != nil {
    log.Fatal(err)
}
// Access verified measurements and keys
tlsKey, err := verified.TLSPublicKeyFP()
if err != nil { log.Fatal(err) }
log.Printf("TLS Cert Fingerprint: %s", tlsKey)
hpkeKey, err := verified.HPKEPublicKey()
if err != nil { log.Fatal(err) }
log.Printf("HPKE Public Key: %s", hpkeKey)
```

## Secure HTTP Client
The `client` package wraps `net/http` and adds:
1. **Attestation gate** – the first request verifies the enclave.
2. **TLS pinning** – the enclave-generated certificate fingerprint is pinned for the session.
3. **Round-tripping helpers** – a mobile-compatible `Request` method.

```go
headers := `{"Content-Type":"application/json"}`
body    := []byte(`{"key": "value"}`)

resp, err := tinfoilClient.Request("POST", "/api/submit", headers, body)
```

For advanced usage retrieve the underlying `*http.Client`:
```go
httpClient, err := tinfoilClient.HTTPClient()
```

## Pinning and refresh

The TLS pin runs for direct HTTPS and HTTPS-over-CONNECT connections. Fetching
the document does not require a separate direct TLS probe. See the
[verification flow](../verify/README.md#v3-verification-flow) for what each
verification checks and how `FreshnessExpiresAt` is derived.

The cached `SecureClient` HTTP clients and the OpenAI SDK's TLS/EHBP transports
check the `FreshnessExpiresAt` deadline before admitting each request, including
redirects and key-rotation retries. Expired or missing verification blocks new
requests until refresh succeeds; refresh errors never authorize requests with
expired keys.
All clients returned by one `SecureClient` share verification state and one
refresh attempt, including explicit `Verify()` calls. The attestation network
fetch is bounded to 30 seconds; local cryptographic verification has no SDK
timeout. A waiting request can cancel without canceling other waiters.

A request admitted before expiration may finish, including a streaming response.
Expiration does not interrupt that request. There is no background refresh.

## Verification options

`client` takes the same policy as
[`verify.NewVerifier`](../verify/README.md#verification-options) as a struct,
because the Swift bindings need a type they can construct and pass across the
FFI boundary:

```go
opts := client.VerificationOptions{
    PinnedRegisters: &measurement.Measurement{
        Type:      measurement.TdxGuestV2,
        Registers: []string{4: rtmr3},
    },
}
secureClient, err := client.NewSecureClient("enclave.example.com", "org/repo", &opts)
```

## Auditing the Client Code

- Fetching, caching and freshness enforcement: this package.
- Per-connection TLS pinning: `roundtrip.go`.
