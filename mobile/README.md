# mobile

The gomobile surface: the one package bound into `Tinfoil.xcframework`. It
exists so the rest of the SDK does not have to be shaped by the FFI.

gomobile carries signed integers, floats, `string`, `bool`, `[]byte`, `error`,
and pointers to structs in a bound package. Not maps, not slices other than
`[]byte`, not struct values, and nothing from an unbound package — so not
`time.Time` or `context.Context`. **What it cannot carry, it drops silently**:
the build still succeeds and the symbol is simply absent in Swift.

Binding the Go client package directly showed what that costs. Its options
struct bound with no properties at all, and its verification result lost
`CryptoMaterial`, `FreshnessExpiresAt` and `Verifier` — the endorsed keys and
the expiry deadline.

So everything structured crosses as a JSON string, and the typed surface is just
`Verifier`. The JSON shape is declared in `verification.go`, not derived from
the SDK's types: callers are never compiled against this module, so a field
rename inside the verifier would otherwise break them silently. That struct is
the contract, and `schema_version` says which version a payload is.

## What the caller does

This package performs no I/O. The caller fetches each attestation document with
its own HTTP stack, from `AttestationURL` with a nonce from `NewNonce`, and
passes the bytes and the nonce to `Verifier.Verify`. Every trust decision stays
here; the app's networking (system proxies, cancellation) carries every
request. The caller owns router discovery, retries and caching, binds its
traffic to the keys a verification returns, and stops authorizing new requests
at `freshness_expires_at`. `Verify` already fails for a result past that
deadline, so verifying again cannot loop on an expired one.

The URL comes from Go rather than being rebuilt by the caller so the wire
format has one definition: the Go SDK fetches through the same function. The
rest of the fetch is the caller's to match: HTTPS only, including every
redirect; a 30 second timeout; a 32 MiB cap on the body; a non-2xx status as a
failure; and a connection of its own rather than one pooled with other
traffic, which may still reach a replica draining after a cutover.

## Errors

Errors flatten to an `NSError` carrying only a message, so the category has to
survive in the text. It does: the SDK's categories lead their messages with
`configuration error:` or `attestation error:`, and fetching is the caller's, so
no fetch error starts here. Nothing in this package adds a prefix of its own. The
prefixes are exported as constants in `errors.go`, so a caller matches on them
instead of on literals. `NewNonce` cannot fail: Go's random source crashes the
program rather than return an error.

## Checking a change

Mistakes here are silent, so look at the generated surface. Without Xcode:

```
go install golang.org/x/mobile/cmd/gobind@$(go list -m -f '{{.Version}}' golang.org/x/mobile)
gobind -lang=objc -outdir=/tmp/gobind github.com/tinfoilsh/tinfoil-go/mobile
grep -E '^(FOUNDATION_EXPORT|@interface|- \()' /tmp/gobind/src/gobind/Mobile.objc.h
```

With Xcode, `scripts/build-mobile.sh` builds the framework and asserts the
header set, and CI type-checks `tests/mobile/Smoke.swift` against it. Neither
catches an export gomobile silently dropped — only the listing above does.
