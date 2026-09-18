# Production Turin snapshots

`inf17.json` and `inf18.json` were captured on 2026-09-18 from the running
`glm-5-3-inf17` and `glm-5-3-inf18` containers, respectively. The Tinfoil CLI
identified both as `tinfoilsh/confidential-glm5-3-nvfp4` release `v0.0.3`.
Each complete nonce-bound v3 document passed `client.VerifyDocumentV3` against
that repository before its report, VCEK, and selected policy were extracted.
The selected policy was `amd-turin-prod` from the authenticated platform
endorsement release `v0.0.14`.

Both version-5 reports have `PLATFORM_INFO=0x64`: ECC, completed alias checking,
and IOMMU write safety are enabled. SMT, TSME, RAPL disabling, ciphertext hiding,
and TIO are false. These values exactly match the signed platform policy.
Consequently the reconciled `amd-turin-prod` fixture retains `ecc_enabled: true`.

The regression test verifies AMD signatures against the pinned Turin roots at
the capture time and enforces the captured platform policy. It deliberately
does not treat these static snapshots as fresh v3 documents or independent
code-provenance fixtures. A fresh production check must fetch a new nonce-bound
document and verify all collateral and witnesses.

The CLI listed only stopped containers on inf19 in the checked organization,
so no inf19 report was captured. No container state was changed.
