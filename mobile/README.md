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
`Client` plus two accessors. The JSON shape is declared in `verification.go`,
not derived from the SDK's types: callers are never compiled against this
module, so a field rename inside the verifier would otherwise break them
silently. That struct is the contract, and `schema_version` says which version a
payload is.

Errors flatten to an `NSError` carrying only a message, so the category has to
survive in the text. It already does: every error reaching this package is one
of the SDK's categories, and their messages lead with `configuration error:`,
`fetch error:` or `attestation error:`. Nothing here rewrites them — a wrapper
that prepended the prefix would print it twice.

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
