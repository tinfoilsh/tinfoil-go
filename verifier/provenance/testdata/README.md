# Private provenance fixtures

`private-source.json` and `private-freshness.json` are unchanged signed bundles
retrieved from `tinfoilsh/private-attestation-e2e` for release `v1.0.1`, digest
`5ea52b374e0ce8da0367c17a7d954392c07dcf26993bc2bc57fa540b9b858baa`.
They contain synthetic measurement values and GitHub-generated certificates,
signatures, and RFC 3161 timestamps; no credentials are included.

- Source: [run 33162108272](https://github.com/tinfoilsh/private-attestation-e2e/actions/runs/33162108272).
- Freshness: [run 33162404555](https://github.com/tinfoilsh/private-attestation-e2e/actions/runs/33162404555).

The freshness run used a test workflow ref and a test-only human actor guard.
The tests verify its cryptographic chain under that exact test identity, then
assert that the production freshness API rejects it. Production qualification
still requires App dispatch of `private.yml@refs/heads/main`; these fixtures do
not establish a measured CVM deployment or production freshness authorization.

`public-log-entry.json` is copied from the existing public attestation fixture
in tinfoil-js (`packages/verifier/test/fixtures/attestation-bundle.json`). Adding
it to the private bundle tests rejection without falling back between trust
profiles. The private fixtures and this entry are byte-identical in Go and JS.
