# Golden files for the report's JSON form

Each file is one case of the JSON form that `VerificationReport.MarshalJSON`
writes:

- `description` says what the case shows.
- `vector`, when present, names a full-verify vector of the shared
  conformance suite, relative to its `vectors/` directory. The case's report
  is what verifying that vector gives, at the vector's verification time.
  `verify/conformance` checks these cases when `TINFOIL_CONFORMANCE_VECTORS`
  is set.
- Without `vector`, the description names the Go test that builds the input,
  and `verify` checks the case.
- `report` is the expected JSON form.

Compare a report with `report` as JSON values, not as bytes: the order of
an object's members carries no meaning. Go compares every member. Another SDK
that reuses these files compares every member except the step messages,
which are each SDK's own text, and `metadata`, which describes the run. It
compares times as instants.

To regenerate the files after an intended change to the form, run
`go test ./verify -run Golden -update` and, with the vectors,
`go test -tags tinfoil_conformance ./verify/conformance -run TestReportJSONGolden -update`.
