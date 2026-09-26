The mobile SDK exports one package, `verifier/mobile`; the package list is
shared by the release build and local generation checks in
`scripts/mobile-packages.txt`. Every other verifier package is a Go API and is
linked as an implementation dependency. See
[verifier/mobile/README.md](../../verifier/mobile/README.md) for why the
binding surface is its own package and what gomobile can carry across.

On macOS, run `bash scripts/setup-mobile.sh`, then
`bash scripts/build-mobile.sh`. The Mobile SDK pull-request workflow builds all
Apple targets and type-checks `Smoke.swift` against the macOS framework. It
creates no release and contacts no enclave.

The typed surface is deliberately small: construct a client, verify, read the
result. Everything structured crosses as a JSON string, so `Smoke.swift` also
decodes a verification payload into `Verification` — gomobile drops what it
cannot represent without failing the build, so a type-check that only touched
method names would not notice a field going missing.

`MobileNewClientWithOptions` takes the policy as a JSON object with
`pinned_registers` and integer `freshness_max_age_ns`; an empty string selects
the default policy.

V3 removes the old attestation-bundle discovery/verification APIs, and this
framework renames the binding surface from `Client*` to `Mobile*`. Swift callers
on `ClientNewSecureClient`, `setAttestationBundleURL` or package-level bundle
helpers must migrate; the payload shape changed too, so decoders written against
`GroundTruth` need rewriting against the schema in
`verifier/mobile/verification.go`. The smoke test covers the supported API and
claims no source compatibility with the v2 surface. Update the Swift package's
binary checksum and release pin only after the Go framework has been published.
