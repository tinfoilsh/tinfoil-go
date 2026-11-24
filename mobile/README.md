# mobile

The gomobile surface: the one package bound into `TinfoilGo.xcframework`, which
[tinfoil-swift](https://github.com/tinfoilsh/tinfoil-swift) uses, and into
`TinfoilGo.aar` for Android. Everything
structured crosses as a JSON string whose shape is declared in
`verification.go`. That struct, `resultJSON`, is the contract, and
`schema_version` says which version a payload is.

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

`NewVerifier` takes a JSON object with two optional members: `config_trust`,
which decides how a deployment's config is authenticated, and `policy`. An
empty string, `{}`, and `null` members select the defaults: configs endorsed
by Tinfoil's public registry, and the default policy. Byte strings are standard
base64 with padding, and keys are PKIX public keys, each one PEM `PUBLIC KEY`
block.

```json
{
  "config_trust": {"type": "registries", "ids": ["<registry ID>"]},
  "policy": {
    "pinned_registers": {"type": "<measurement type>", "registers": ["<hex>", "..."]},
    "freshness_max_age_ns": 3600000000000,
    "artifacts": {"type": "endorsed", "freshness_keys_pem": ["<PEM>"]}
  }
}
```

`config_trust` and `policy.artifacts` are tagged objects: `type` selects the
variant, and each variant takes only its own members.

| `config_trust` | Go verifier input |
|---|---|
| `{"type": "registries", "ids": [...]}` (include `PublicRegistryID` to keep the public registry) | `verify.Registries` |
| `{"type": "signing_keys", "keys_pem": [...]}` | `verify.ConfigSigningKeys` |
| `{"type": "embedded_config", "name"?, "bytes"}` | `verify.EmbeddedConfig` |
| `{"type": "embedded_config_reference", "name"?, "digest", "runtime": {"repo", "tag", "digest"}}` | `verify.EmbeddedConfigReference` |

| `policy` member | Go verifier input |
|---|---|
| `pinned_registers` (`{type, registers}`) | `Policy.PinnedRegisters` |
| `freshness_max_age_ns` (integer) | `Policy.FreshnessMaxAge` |
| `artifacts`: `{"type": "endorsed", "freshness_keys_pem"?: [...]}` | `Policy.Artifacts` as `verify.EndorsedArtifacts` |
| `artifacts`: `{"type": "embedded", "runtime"?, "platform"?, "freshness_keys_pem"?: [...]}` | `Policy.Artifacts` as `verify.EmbeddedArtifacts` |

An absent `freshness_keys_pem` selects Tinfoil's public freshness keys. The
parser rejects malformed JSON, a duplicate or unknown member, an unknown
`type`, and a member that does not belong to the chosen `type`. The verifier's
own checks apply on top, for example to an empty key list, or to freshness
keys when both the runtime and the platform are embedded.

For example, a verifier that takes an embedded config and runtime, and an
endorsed platform:

```json
{
  "config_trust": {"type": "embedded_config", "name": "/org/project/v1", "bytes": "<base64>"},
  "policy": {"artifacts": {"type": "embedded", "runtime": "<base64>"}}
}
```

## Config authorizer

`NewVerifierWithConfigAuthorizer(policyJSON, authorizer)` takes the
authorizer as the config trust (`verify.ConfigAuthorizer`), so its JSON is the
policy object alone, in the shape of the `policy` member above, and a
`config_trust` member there is rejected as unknown. gomobile cannot
carry a Go function, so the callback is the `ConfigAuthorizer` interface, which
Swift implements; Swift imports it as `MobileConfigAuthorizerProtocol`, because
gomobile also emits a proxy class named `MobileConfigAuthorizer`. Go calls
`authorizeConfig` synchronously inside `verify`, possibly on several threads at
once, with the document's untrusted config material as JSON, whose byte
strings (the config, the Sigstore bundle and the issuer certificate) are base64
of the document's exact bytes. A thrown error
rejects the document at the provenance layer with the error's message.

## Checks before I/O

`Verifier.CheckPinVerifiability(repo, project)` returns the usage error that
`Verify` would return for that pin whatever the document, so that a client can
refuse a pin before fetching anything; either may be empty. `Verify` can still
return a usage error for a pin that passed, once it has the document. `Verifier.CallerAuthorizesConfig()` reports a
verifier that takes an embedded config or a config authorizer; such a verifier
needs an explicit enclave and cannot be used to discover a router.

## Result

`Verify` returns one result JSON, declared and documented on `resultJSON` in
`verification.go`, for both outcomes of a verification that ran, because
gomobile can't carry a report on an error:

- **Accepted:** `report.verified_facts` holds what the document proved, and
  there is no `error`.
- **Rejected:** `error` holds the layer and the message (in the format under
  [Errors](#errors)), and `report.partial_facts` holds what the steps before
  the failure established. The caller throws its verification error with the
  report.

Either way, `report.steps` lists the four layers (`envelope`, `provenance`,
`quote`, `policy`) in order, each `passed`, `failed`, `skipped` or `not_run`;
a failed step's `message` is the failing check's message without the prefix
that `error.message` carries. `report.metadata.verified_at` is the appraisal
instant. Verified facts from a verification against a config also carry `config`, `runtime` and
`platform`, each with the `source` that it was accepted from (`endorsement`,
`embedded`, or `policy` for a config that an authorizer approved). Channel
keys come only from `verified_facts`; partial facts hold key fingerprints,
which are unverified.

## Errors

Errors reach Swift as an `NSError` carrying only a message. `Verify` returns
an error rather than a result only when there is no report: a usage error,
and a document that verified but whose freshness deadline passed before
`Verify` returned. Every error this package returns, and every result's
`error.message`, leads with `UsageErrorPrefix` or `VerificationErrorPrefix`
from `errors.go`, so callers match on those constants instead of on
literals. A
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

## Android

`scripts/build-mobile-android.sh` builds `TinfoilGo.aar` for `arm64-v8a`,
`armeabi-v7a` and `x86_64` with the NDK named in
`scripts/android-ndk-version.txt`. The package is bound as
`sh.tinfoil.go.mobile`: the functions and constants are static members of
`Mobile`, `Verifier` is a class, and `ConfigAuthorizer` is an interface that
the caller implements. Errors reach Java as a `java.lang.Exception` carrying
only a message, with the same prefixes as above.

The script asserts that only this package is exported, that no library built
without `tinfoil_conformance` carries a test-only entry point, and that the
64-bit libraries load on devices with 16 KiB pages. An app can hold one
gomobile library: a second one would bring its own `libgojni.so` and `go.Seq`
class. To list the generated surface without building, pass `-lang=java
-javapkg=sh.tinfoil.go` to `gobind`, and read
`java/sh/tinfoil/go/mobile/*.java` under the output directory.

## Conformance build

Built with `-tags tinfoil_conformance` (`MOBILE_BUILD_TAGS=tinfoil_conformance
scripts/build-mobile.sh`), the framework also exports
`NewDangerousTestOnlyVerifier`, which trusts a conformance vector's anchors, and
`Verifier.DangerousTestOnlyVerifyAt`, which sets the appraisal clock
([`conformance.go`](conformance.go)). tinfoil-swift runs the suite's
full-verify vectors through them. A released framework never carries them, and
`scripts/build-mobile.sh` refuses a build without the tag that does.
`TestConformanceVectorsMatchTheAdapter` asserts that each full-verify vector gets
the same verdict through them as through Go's own adapter, with one expected
exception: like the Go client, the binding treats a result as expired at the
instant that its freshness witnesses reach their maximum age, which the
verifier still accepts, and `fr2-pos-at-max-age` replays that instant.
