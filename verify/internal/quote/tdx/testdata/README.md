`historical.json` contains a synthetic TDX quote, Intel-style certificate chains,
and signed collateral from the Python SDK's historical-verification tests in
[PR #128](https://github.com/tinfoilsh/tinfoil-python/pull/128). The root is test-only.

Each case replays the base evidence with the listed signed response bodies.
The future TCB Info and QE Identity cases are issued one second after appraisal;
the boundary case is issued exactly at appraisal. Expired collateral and a revoked
PCK certificate remain rejected. No network access or private keys are required.
