The mobile SDK exports `verifier/client` and `verifier/measurement`; the exact
package list is shared by the release build and local generation checks in
`scripts/mobile-packages.txt`. Other verifier packages remain Go APIs and are
linked as implementation dependencies.

On macOS, run `bash scripts/setup-mobile.sh`, then
`bash scripts/build-mobile.sh`. The Mobile SDK pull-request workflow builds all
Apple targets and type-checks `Smoke.swift` against the macOS framework. It
creates no release and contacts no enclave.

`ParseVerificationOptionsJSON` accepts `pinned_registers`, workload `pinned_code`
and `pinned_shape`, and integer `freshness_max_age_ns` options. Workload pins
require an explicit enclave, an empty repository argument, and no
`pinned_registers`; TDX requires a shape. Pass the result to constructors or verification;
`nil` uses defaults. See [Smoke.swift](Smoke.swift)
for client construction and offline verification examples.

Compiling and running `Smoke.swift` executes `checkWorkloadPinSurface()`, which
checks JSON option decoding and client construction without network access.

V3 removes the old attestation-bundle discovery/verification APIs. Swift callers
using `setAttestationBundleURL` or package-level bundle helpers must migrate to
the v3 enclave document flow before adopting this framework. The smoke test
covers the retained client API; it does not claim source compatibility with
those removed v2 APIs. Update the Swift package's binary checksum and release
pin only after the Go framework has been published.
