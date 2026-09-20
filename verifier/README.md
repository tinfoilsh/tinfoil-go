# Tinfoil Verifier

Portable remote-attestation verifier & secure HTTP client for enclave-backed services.

[![Build Status](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions)

## Overview
Tinfoil Verifier is a Go library that verifies the integrity of remote enclaves (AMD SEV-SNP & Intel TDX) and binds that verification to TLS connections. It also ships a drop-in secure `http.Client` that performs attestation transparently.

## Features
- **Hardware-rooted remote attestation** for AMD SEV-SNP & Intel TDX
- **Self-contained** with no external attestation service
- **Secure HTTP client** with automatic TLS certificate pinning
- **Sigstore integration** for code provenance verification
- **Attested HPKE public keys** for use with [EHBP](https://docs.tinfoil.sh/resources/ehbp) clients
- **Swift bindings** via gomobile for iOS/macOS integration

## Installation
```bash
go get github.com/tinfoilsh/tinfoil-go@latest
```

## Quick Start
```go
import "github.com/tinfoilsh/tinfoil-go/verifier/client"

// 1. Create a client
tinfoilClient := client.NewSecureClient("enclave.example.com", "org/repo")

// 2. Perform HTTP requests – attestation happens automatically
resp, err := tinfoilClient.Get("/api/data", nil)
if err != nil {
    log.Fatal(err)
}
log.Printf("Status: %s, Body: %s", resp.Status, string(resp.Body))
```

To verify manually and expose the verification state:
```go
groundTruth, err := tinfoilClient.Verify()
if err != nil {
    log.Fatal(err)
}
// Access verified measurements and keys
log.Printf("TLS Cert Fingerprint: %s", groundTruth.TLSPublicKey)
log.Printf("HPKE Public Key: %s", groundTruth.HPKEPublicKey)
```

## Secure HTTP Client
The `client` package wraps `net/http` and adds:
1. **Attestation gate** – the first request verifies the enclave.
2. **TLS pinning** – the enclave-generated certificate fingerprint is pinned for the session.
3. **Round-tripping helpers** – convenience `Get`, `Post` methods.

```go
headers := map[string]string{"Content-Type": "application/json"}
body    := []byte(`{"key": "value"}`)

resp, err := tinfoilClient.Post("/api/submit", headers, body)
```

For advanced usage retrieve the underlying `*http.Client`:
```go
httpClient, err := tinfoilClient.HTTPClient()
```

## Remote Attestation
Tinfoil Verifier currently supports two platforms:

| Platform       | Technique                                | Docs                                                  |
|----------------|------------------------------------------|-------------------------------------------------------|
| **AMD SEV-SNP**| VCEK certificates & SNP report validation | [AMD Spec](https://www.amd.com/en/developer/sev.html)  |
| **Intel TDX** | TDX quote validation & TD report checks   | [Intel Guide](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) |

### V3 verification flow

The client generates a fresh nonce and fetches one document from
`https://<enclave>/.well-known/tinfoil-attestation?nonce=<nonce>`. The document
carries CPU evidence, attested transport keys, and all required verification
collateral. Verification then runs offline using the embedded trust roots:

1. Strictly parse the envelope and check the nonce and endorsed-section hashes.
2. Authenticate code provenance, platform policy, and their freshness witnesses.
3. Authenticate the CPU quote and enforce the complete code/platform policy.
4. Use the endorsed TLS key for each HTTPS connection, or the endorsed HPKE key
   when selecting EHBP. A TLS-only enclave may omit HPKE material.

The TLS pin runs for direct HTTPS and HTTPS-over-CONNECT connections. Fetching
the document does not require a separate direct TLS probe. Code and platform
witnesses have a seven-day maximum age by default; the earliest authenticated
expiry is exposed by `VerifyV3` and `VerifyDocumentV3` as `FreshnessExpiresAt`.
Callers using these APIs must retain the deadline and stop authorizing new
requests at or after it, then verify again before accepting more requests.
Re-verifying unchanged witnesses does not extend their deadline.

The cached `SecureClient` HTTP clients and the OpenAI SDK's TLS/EHBP transports
check this deadline before admitting each request, including redirects and
key-rotation retries. Expired or missing verification blocks new requests until
refresh succeeds; refresh errors never authorize requests with expired keys.
All clients returned by one `SecureClient` share verification state and one
refresh attempt, including explicit `Verify()` calls. The attestation network
fetch is bounded to 30 seconds; local cryptographic verification has no SDK
timeout. A waiting request can cancel without canceling other waiters.

A request admitted before expiration may finish, including a streaming response.
Expiration does not interrupt that request. There is no background refresh.

### Migration from v2

The v3 client always requests a nonce-bound v3 document. Enclaves serving only
legacy v2 documents must upgrade before using this verifier.
Remove calls to `SetNoncedAttestation`; nonce binding is mandatory in v3.
`HardwareMeasurement` is removed; the authenticated MRTD and RTMR0 are the
first two registers of the TDX enclave measurement.

The old `verifier/attestation`, `verifier/sigstore`, `verifier/github`, and
`verifier/config` packages are removed. Measurement types now live in
`verifier/measurement`. The legacy `SetAttestationBundleURL`, `VerifyFromBundle`,
`FetchAndVerifyJSON`, `FetchAndVerifyFromURLJSON`, and `VerifyFromBundleJSON`
entry points are removed; use an explicit enclave/repository and `VerifyV3`.
V3 verification obtains collateral from the enclave document, so it no longer
fetches reference values through the old bundle service.

For an already fetched document, use:

```go
verified, err := client.VerifyDocumentV3(documentBytes, expectedNonce, trustedRepo)
```

The repository and nonce are caller-owned expectations. After success, bind
service traffic to the returned TLS/HPKE material and honor `FreshnessExpiresAt`.
This low-level function does not open a service connection or enforce a cache's
expiration on the caller's behalf. Swift callers using the removed bundle APIs
also need to migrate before adopting the v3 framework.

## Verification options

Pass `client.VerificationOptions` to the `*WithOptions` APIs to set register pins
or `FreshnessMaxAge`. Empty pin entries retain defaults; TDX order is
`[MRTD, RTMR0, RTMR1, RTMR2, RTMR3]`. Pins cannot override release or platform measurements.

```go
import "github.com/tinfoilsh/tinfoil-go/verifier/measurement"

opts := client.VerificationOptions{
    PinnedRegisters: &measurement.Measurement{
        Type:      measurement.TdxGuestV2,
        Registers: []string{4: rtmr3},
    },
}
secureClient, err := client.NewSecureClientWithOptions("enclave.example.com", "org/repo", opts)
```

## JavaScript / TypeScript / WASM

### JavaScript / TypeScript SDK

For production JavaScript/TypeScript applications, use the [tinfoil-js](https://github.com/tinfoilsh/tinfoil-js) package, which provides:
- OpenAI-compatible API with built-in verification
- Native JavaScript verification implementation
- EHBP (Encrypted HTTP Body Protocol) for end-to-end encryption
- Support for browsers, Node.js 20+, Deno, Bun, and Cloudflare Workers
- Comprehensive verification reporting with step-by-step diagnostics

```bash
npm install tinfoil
```

See the [tinfoil-js documentation](https://github.com/tinfoilsh/tinfoil-js) for usage examples.

## Auditing the Verification Code

- Envelope parsing and nonce/hash binding: `envelope/envelope.go`.
- Code, platform and freshness provenance: `provenance/`.
- Strict platform-policy parsing: `policy/`.
- CPU authentication and expectation enforcement: `quote/sev/` and `quote/tdx/`.
- End-to-end verification: `client/verify.go`.
- Per-connection TLS pinning: `client/roundtrip.go`.
