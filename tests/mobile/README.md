# Mobile smoke test

`Smoke.swift` type-checks the supported Swift API of `TinfoilGo.xcframework`,
including decoding a verification payload, since gomobile drops what it cannot
represent without failing the build. See [mobile/README.md](../../mobile/README.md)
for the binding contract.

On macOS, run `bash scripts/setup-mobile.sh`, then `bash scripts/build-mobile.sh`.
The Mobile SDK pull-request workflow builds all Apple targets and type-checks
`Smoke.swift` against the macOS framework. It creates no release and contacts
no enclave.

The bound packages are listed in `scripts/mobile-packages.txt`, shared by the
release build and local checks. Update the Swift package's binary checksum and
release pin only after the Go framework has been published.
