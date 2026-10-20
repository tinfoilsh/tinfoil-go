# mobile

The gomobile surface: the one package bound into `Tinfoil.xcframework`, which
[tinfoil-swift](https://github.com/tinfoilsh/tinfoil-swift) uses. Everything
structured crosses as a JSON string whose shape is declared in
`verification.go`. That struct is the contract, and `schema_version` says which
version a payload is.

## What the caller does

This package performs no I/O. The caller:

- fetches each attestation document from `AttestationURL` with a nonce from
  `NewNonce`, and passes the bytes and the nonce to `Verifier.Verify`;
- fetches over HTTPS only, including every redirect, with a 30 second timeout,
  a 32 MiB cap on the body, a non-2xx status treated as a failure, and a
  connection of its own rather than one pooled with other traffic;
- owns router discovery, retries and caching, binds its traffic to the keys a
  verification returns, and stops authorizing new requests at
  `freshness_expires_at`.

`NewVerifier` takes the policy as a JSON object with `pinned_registers` and
integer `freshness_max_age_ns`; an empty string selects the default policy.

## Errors

Errors reach Swift as an `NSError` carrying only a message. Every error this
package returns leads with `UsageErrorPrefix` or `VerificationErrorPrefix` from
`errors.go`, so callers match on those constants instead of on literals. A
verification error's message then names the layer that rejected the document
(`envelope`, `provenance`, `quote` or `policy`) and `: `, as in
`verification error: quote: <detail>`.

## Checking a change

gomobile silently drops what it cannot carry (maps, slices other than
`[]byte`, struct values, and types from unbound packages such as `time.Time`):
the build still succeeds and the symbol is simply absent in Swift. Without
Xcode, list the generated surface:

```
go install golang.org/x/mobile/cmd/gobind@$(go list -m -f '{{.Version}}' golang.org/x/mobile)
gobind -lang=objc -outdir=/tmp/gobind github.com/tinfoilsh/tinfoil-go/mobile
grep -E '^(FOUNDATION_EXPORT|@interface|- \()' /tmp/gobind/src/gobind/Mobile.objc.h
```

With Xcode, `scripts/build-mobile.sh` builds the framework and asserts the
header set, and CI type-checks [`tests/mobile/Smoke.swift`](../tests/mobile/Smoke.swift)
against it. Neither catches an export gomobile silently dropped; only the
listing above does.
