# Tinfoil Verifier

Portable remote-attestation verifier for enclave-backed services.

[![Build Status](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions)

## Overview
Tinfoil Verifier is a Go library that verifies the integrity of remote enclaves (AMD SEV-SNP & Intel TDX). The [secure client](../client/README.md) fetches documents, caches verifications and binds TLS connections to them.

## Features
- **Hardware-rooted remote attestation** for AMD SEV-SNP & Intel TDX
- **Self-contained** with no external attestation service
- **Sigstore integration** for code provenance verification
- **Attested HPKE public keys** for use with [EHBP](https://docs.tinfoil.sh/resources/ehbp) clients
- **Swift bindings** via gomobile for iOS/macOS integration

## Installation
```bash
go get github.com/tinfoilsh/tinfoil-go@latest
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

1. Strictly parse the document and check the nonce and endorsed-section hashes.
2. Authenticate code provenance, platform policy, and their freshness witnesses.
3. Authenticate the CPU quote and enforce the complete code/platform policy.
4. Use the endorsed TLS key for each HTTPS connection, or the endorsed HPKE key
   when selecting EHBP. A TLS-only enclave may omit HPKE material.

Code and platform witnesses have a seven-day maximum age by default; the
earliest authenticated expiry is exposed by `VerifyV3`, `Verify` and
`VerifyDocumentV3` as `FreshnessExpiresAt`.
Callers using these APIs must retain the deadline and stop authorizing new
requests at or after it, then verify again before accepting more requests.
Re-verifying unchanged witnesses does not extend their deadline. The
[secure client](../client/README.md#pinning-and-refresh) enforces this deadline
for its own requests.

### Verifying a document you already hold

`verify.Verifier` appraises a document offline. It opens no connections,
holds no cache and is immutable, so it is safe for concurrent use — fetching
the document, caching the result and enforcing its deadline stay with the
caller.

By default, `VerifyV3` samples the appraisal clock once and
judges the freshness witnesses against that instant; the CPU evidence layer
reads the clock separately for vendor certificate and CRL validity windows,
because a production build cannot pass an instant down to it. So the same
document is accepted today and rejected once its witnesses go stale. What a
successful verification reports does not drift, though: `FreshnessExpiresAt` is
derived from the authenticated witness timestamps, never from the local clock.

For archived documents, `verify.WithIgnoreFreshness()` skips both freshness
witness checks and leaves `FreshnessExpiresAt` zero. Code and platform
provenance, CPU evidence, and certificate/collateral validity checks still apply.
This option is only available on the core verifier; it does not authorize live
SDK requests with expired evidence.

```go
import "github.com/tinfoilsh/tinfoil-go/verify"

verifier, err := verify.NewVerifier()
if err != nil {
    return err
}
verified, err := verifier.VerifyV3(documentBytes, expectedNonce, trustedRepo)
if err != nil {
    return err
}
```

The nonce and the repository reference are caller-owned expectations; the
document cannot supply either. After success, bind service traffic to the
returned TLS/HPKE material and stop authorizing new requests at
`FreshnessExpiresAt`.

`client.VerifyDocumentV3` wraps this with the `VerificationOptions` struct the
Swift bindings need, and [`client.SecureClient`](../client/README.md) adds
fetching, caching and transport binding on top.

### Migration from v2

The v3 client always requests a nonce-bound v3 document. Enclaves serving only
legacy v2 documents must upgrade before using this verifier.
Remove calls to `SetNoncedAttestation`; nonce binding is mandatory in v3.
`HardwareMeasurement` is removed; the authenticated MRTD and RTMR0 are the
first two registers of the TDX enclave measurement.

The old `verifier/attestation`, `verifier/sigstore`, `verifier/github`, and
`verifier/config` packages are removed. Measurement types now live in
`verify/measurement`. The legacy `SetAttestationBundleURL`, `VerifyFromBundle`,
`FetchAndVerifyJSON`, `FetchAndVerifyFromURLJSON`, and `VerifyFromBundleJSON`
entry points are removed; use an explicit enclave/repository and `Verify`.
V3 verification obtains collateral from the enclave document, so it no longer
fetches reference values through the old bundle service.

For an already fetched document, use `verify.Verifier` — see [Verifying a
document you already hold](#verifying-a-document-you-already-hold).
`client.VerifyDocumentV3` remains for callers already built on it. Neither
opens a service connection or enforces a cache's expiration on the caller's
behalf. Swift callers using the removed bundle APIs also need to migrate before
adopting the v3 framework.

## Verification options

Register pins and the freshness bound are fixed when a verifier is built and
cannot change afterwards. Empty pin entries retain defaults; TDX order is
`[MRTD, RTMR0, RTMR1, RTMR2, RTMR3]`. Pins cannot override release or platform
measurements, and `FreshnessMaxAge` defaults to seven days.

`verify.NewVerifier` takes functional options:

```go
import (
    "time"

    "github.com/tinfoilsh/tinfoil-go/verify"
    "github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

verifier, err := verify.NewVerifier(
    verify.WithPinnedRegisters(&measurement.Measurement{
        Type:      measurement.TdxGuestV2,
        Registers: []string{4: rtmr3},
    }),
    verify.WithFreshnessMaxAge(24*time.Hour),
)
```

The secure client takes the same policy as a
[struct](../client/README.md#verification-options).

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

- Document parsing and nonce/hash binding: `../document/document.go`.
- Code, platform and freshness provenance: `internal/provenance/`.
- Strict platform-policy parsing: `internal/policy/`.
- CPU authentication and expectation enforcement: `internal/quote/sev/` and
  `internal/quote/tdx/`.
- End-to-end verification: `verifier.go`.
- Fetching, caching, freshness enforcement and TLS pinning: see the
  [secure client](../client/README.md#auditing-the-client-code).

## Arbitrary endorsed material

A successful `VerifyV3`, `Verify` or `VerifyDocumentV3` result retains every endorsed
`CryptoMaterial` item. Select by exact ID and format:

```go
data, err := verified.CryptoMaterialData("host-ssh", document.KeySPKIV1Format)
if err != nil {
    return err
}
// data is lowercase hex of full DER SPKI. Decode and validate the key for
// your application's protocol before binding a connection to it.
```

Unknown valid formats are preserved. The SDK does not add protocol-specific
key adapters; SSH conversion and pin installation belong to the CLI/consumer.
Use only successfully verified results and retain the expected workload and
`FreshnessExpiresAt` context. Lookup does not refresh or check expiry. Exporting
a static pin records an enrollment decision; native clients do not enforce the
attestation's expiry on subsequent connections.
