# Tinfoil Verifier

Portable remote-attestation verifier for enclave-backed services.

[![Build Status](https://github.com/tinfoilsh/tinfoil-go/actions/workflows/sdk-test.yml/badge.svg)](https://github.com/tinfoilsh/tinfoil-go/actions)

## Overview
Tinfoil Verifier is a Go library that verifies the integrity of remote enclaves (AMD SEV-SNP & Intel TDX). The [enclave handle](../enclave/README.md) fetches documents, caches verifications and binds TLS connections to them.

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
earliest authenticated expiry is exposed by `VerifyV3` and the enclave
handle's `Verify` as `FreshnessExpiresAt`.
Callers using these APIs must retain the deadline and stop authorizing new
requests at or after it, then verify again before accepting more requests.
Re-verifying unchanged witnesses does not extend their deadline. The
[enclave handle](../enclave/README.md#pinning-and-refresh) enforces this deadline
for its own requests.

### IGVM runtime pins

For config-based verification, the verifier reads only `cvm-version` to select
the runtime. The pin is `<version>[+gpu]@sha256:<digest>`: a full semantic
version with an optional `v` prefix and prerelease, followed by a 64-character
lowercase hexadecimal manifest digest. Other build metadata is rejected.
The release tag excludes `+gpu`; the hash binds the complete manifest bytes.

Manifest format 2 uses `igvm.variants.cpu` for an unqualified pin and
`igvm.variants.gpu` for `+gpu`. The authenticated CPU quote determines whether
to compare that entry's SNP or TDX measurements. Format 1 retains its single
measurement set and rejects selectors. The config hash binds the original
config bytes; the verifier does not validate the workload's other fields.

### Verifying a document you already hold

`verify.Verifier` appraises a document offline. It opens no connections,
holds no cache and is immutable, so it is safe for concurrent use — fetching
the document, caching the result and enforcing its deadline stay with the
caller.

By default, `VerifyV3` samples the appraisal clock once and judges the
freshness witnesses and the vendor certificate and CRL validity windows
against that instant. So the same document is accepted today and rejected once
its witnesses go stale. What a
successful verification reports does not drift, though: `FreshnessExpiresAt` is
derived from the authenticated witness timestamps, never from the local clock.

To appraise an archived document as of an earlier instant, `VerifyV3At` takes
that instant in place of the clock for every one of those checks, and reports
it as `Metadata.VerifiedAt`. The caller must authenticate the instant
independently, for example from a trusted timestamp recorded when the document
was received: an earlier instant accepts collateral that has since expired or
been revoked.

The freshness checks cannot be skipped: an archived document must keep the
freshness witnesses and approvals it carried, and `VerifyV3At` judges them at
that instant like everything else.

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

[`enclave.Handle`](../enclave/README.md) adds fetching, caching and
transport binding on top.

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
It opens no service connection and does not enforce a cache's expiration on
the caller's behalf. Swift callers using the removed bundle APIs also need to migrate before
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

The enclave handle takes the same policy as a
[struct](../enclave/README.md#verification-options).

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

- Document parsing and nonce/hash binding: `document/document.go`.
- Code, platform and freshness provenance: `internal/provenance/`.
- Strict platform-policy parsing: `internal/policy/`.
- CPU authentication and expectation enforcement: `internal/quote/sev/` and
  `internal/quote/tdx/`.
- End-to-end verification: `verifier.go`.
- Fetching, caching, freshness enforcement and TLS pinning: see the
  [enclave handle](../enclave/README.md#auditing-the-handle-code).

## Arbitrary endorsed material

A successful `VerifyV3` or `Verify` result retains every endorsed
`CryptoMaterial` item. Select by exact ID and format:

```go
data, ok := verified.CryptoMaterialData("host-ssh", document.KeySPKIV1Format)
if !ok {
    return fmt.Errorf("document endorses no host-ssh key")
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
