# mobile

The gomobile surface: the one package bound into `TinfoilGo.xcframework`, which
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

## Options

`NewVerifier` takes the policy as a JSON object; an empty string selects the
default policy. Every member is optional, `null` counts as absent, and an
unknown or malformed member is rejected. Byte strings are standard base64 with
padding.

| member | verifier option |
|---|---|
| `pinned_registers` (`{type, registers}`) | `WithPinnedRegisters` |
| `freshness_max_age_ns` (integer) | `WithFreshnessMaxAge` |
| `config_registry_ids` (strings; include `PublicRegistryID` to keep the public registry) | `WithConfigRegistryIDs` |
| `config_signing_keys_pem`, `freshness_signing_keys_pem` (PEM `PUBLIC KEY` blocks) | `WithConfigSigningKeys`, `WithFreshnessSigningKeys` |
| `embedded_config` (`{name?, bytes}` or `{name?, digest, runtime: {repo, tag, digest}}`), `embedded_runtime`, `embedded_platform` | `WithEmbeddedReferences` |

The verifier's own checks apply on top, including the conflicts between trust
sources (for example, registry IDs with config signing keys).

## Config authorizer

`NewVerifierWithConfigAuthorizer` adds `WithConfigAuthorizer`. gomobile cannot
carry a Go function, so the callback is the `ConfigAuthorizer` interface, which
Swift implements; Swift imports it as `MobileConfigAuthorizerProtocol`, because
gomobile also emits a proxy class named `MobileConfigAuthorizer`. Go calls
`authorizeConfig` synchronously inside `verify`, possibly on several threads at
once, with the document's untrusted config material as JSON. A thrown error
rejects the document at the provenance layer with the error's message.

## Checks before I/O

`Verifier.CheckRepoVerifiability(repo)` returns the usage error that `Verify`
would return for `repo` whatever the document, so that a client can refuse a
pin before fetching anything. `Verifier.CallerAuthorizesConfig()` reports a
verifier that takes an embedded config or a config authorizer; such a verifier
needs an explicit enclave and cannot be used to discover a router.

## Result

`Verify` returns the JSON declared in `verification.go`. A verification against
a config also carries `config`, `runtime` and `platform`, each with the
`source` that it was accepted from (`endorsement`, `embedded`, or `policy` for
a config that an authorizer approved).

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
