package verify

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// updateGolden rewrites the golden files of the report's JSON form from what
// the code produces: go test ./verify/... -run Golden -update.
var updateGolden = flag.Bool("update", false, "rewrite the report JSON golden files")

// reportJSONGoldenDir holds the golden files of the report's JSON form. A
// file whose "vector" names a full-verify vector of the conformance suite is
// checked by verify/conformance; the others, by this package.
const reportJSONGoldenDir = "testdata/report-json"

// requireGolden checks report's JSON form against the golden file name, or
// rewrites the file's report with -update.
func requireGolden(t *testing.T, name string, report *VerificationReport) {
	t.Helper()
	got, err := json.Marshal(report)
	require.NoError(t, err)
	requireReportJSONGolden(t, filepath.Join(reportJSONGoldenDir, name+".json"), got, *updateGolden)
}

// requireReportJSONGolden compares got, a report's JSON form, with the
// "report" member of the golden file at path, or rewrites that member with
// got when update is set. Both are compared as JSON values.
func requireReportJSONGolden(t *testing.T, path string, got []byte, update bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var golden map[string]jsontext.Value
	require.NoError(t, json.Unmarshal(data, &golden))
	if update {
		golden["report"] = jsontext.Value(got)
		out, err := json.Marshal(golden, json.Deterministic(true), jsontext.WithIndent("  "))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, append(out, '\n'), 0o644))
		return
	}
	require.JSONEq(t, string(golden["report"]), string(got))
}

// The appraisal instant of the golden cases, in a zone other than UTC so
// that the form's conversion to UTC shows.
var goldenAt = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("east", 3600))

// Every reference value is embedded, so provenance is skipped, and the quote
// step rejects a quote that isn't authentic: expected facts without the full
// measurement, and measured facts without a CPU measurement.
func TestReportJSONGoldenQuoteRejectionAfterSkippedProvenance(t *testing.T) {
	v, err := newEmbeddedVerifier(embeddedInputs(t))
	require.NoError(t, err)
	raw, nonce, _ := embeddedDocument(t, collateral.FormatV3)
	_, err = v.VerifyV3At(raw, nonce, Pin{}, goldenAt)
	requireGolden(t, "rejection-quote-skipped-provenance", requireReport(t, err, LayerQuote, goldenAt))
}

// A document that endorses no keys passes the envelope step with nothing to
// measure, so the report holds "measured": {}.
func TestReportJSONGoldenProvenanceRejectionWithoutKeys(t *testing.T) {
	v, err := NewVerifier(nil, Policy{})
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3},
		func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyV3At(raw, nonce, Pin{Project: "org/project"}, goldenAt)
	report := requireReport(t, err, LayerProvenance, goldenAt)
	require.Equal(t, &MeasuredFacts{}, report.PartialFacts.Measured)
	requireGolden(t, "rejection-provenance-no-keys", report)
}

// goldenConfigFacts are verified facts of a config-based verification on
// SEV-SNP, with every record member and times in a zone other than UTC.
func goldenConfigFacts() *VerifiedFacts {
	zone := time.FixedZone("west", -5*3600)
	approved := time.Date(2026, time.September, 20, 3, 0, 0, 500, zone)
	launch := measurement.Register{0xAB, 0xCD}
	return &VerifiedFacts{
		configRepo:         "tinfoilsh/cvmimage",
		codeDigest:         strings.Repeat("0a", 32),
		codeTag:            "v0.15.0",
		codeMeasurement:    measurement.ExpectedSEVSNP{Launch: &launch},
		enclaveMeasurement: measurement.SEVSNP{Launch: launch},
		config: &ConfigVerification{
			Source: SourceEndorsement, Name: "/org/project/v1", Digest: strings.Repeat("0c", 32),
			Reference: "org/project@v1", SigningKeyHint: "hint", ApprovalTime: approved,
			RegistryID: "registry", SignatureTime: approved.Add(time.Minute),
		},
		runtime: &ArtifactVerification{
			Source: SourceEndorsement, Repo: "tinfoilsh/cvmimage", Tag: "v0.15.0", Digest: strings.Repeat("0a", 32),
			Name: "runtime", Commit: strings.Repeat("0e", 20), ApprovalTime: approved,
		},
		platform: &ArtifactVerification{Source: SourceEmbedded, Digest: strings.Repeat("0f", 32)},
		cryptoMaterial: []document.CryptoMaterialItem{
			{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: strings.Repeat("ab", 32)},
			{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: strings.Repeat("11", 32)},
		},
		freshnessExpiresAt: time.Date(2026, time.October, 3, 7, 0, 0, 0, zone),
	}
}

// A config-based verification's facts, which no shared vector produces:
// every record member, and times converted to UTC. The report is built
// rather than verified, so other SDKs build the same facts to reuse it.
func TestReportJSONGoldenConfigFacts(t *testing.T) {
	report := &VerificationReport{
		Steps: []Step{
			{Layer: LayerEnvelope, Status: StepPassed},
			{Layer: LayerProvenance, Status: StepPassed},
			{Layer: LayerQuote, Status: StepPassed},
			{Layer: LayerPolicy, Status: StepPassed},
		},
		VerifiedFacts: goldenConfigFacts(),
		Metadata:      VerificationMetadata{Verifier: SoftwareIdentity{Name: sdkinfo.Name, Version: "devel"}, VerifiedAt: goldenAt},
	}
	requireGolden(t, "acceptance-config-facts", report)
}

// json.Marshal of verified facts on their own gives the verified_facts
// object of the report, rather than {} for the unexported fields.
func TestVerifiedFactsJSONIsTheReportMember(t *testing.T) {
	facts := goldenConfigFacts()
	report, err := json.Marshal(&VerificationReport{VerifiedFacts: facts})
	require.NoError(t, err)
	var members map[string]jsontext.Value
	require.NoError(t, json.Unmarshal(report, &members))
	for _, v := range []any{facts, *facts} {
		got, err := json.Marshal(v)
		require.NoError(t, err)
		require.JSONEq(t, string(members["verified_facts"]), string(got))
	}
	require.NotContains(t, string(members["verified_facts"]), "tls_public_key_fp", "the keys are in crypto_material only")
	require.NotContains(t, string(members["verified_facts"]), "hpke_public_key\"")
}

// A code measurement holds only the registers that the release fixes, and is
// omitted when it fixes none; a register is never "".
func TestReportJSONCodeMeasurement(t *testing.T) {
	rtmr1 := measurement.Register{0x01}
	for _, tc := range []struct {
		code measurement.Expected
		want string
	}{
		{measurement.ExpectedTDX{RTMR1: &rtmr1}, `{"platform":"tdx","rtmr1":"` + rtmr1.String() + `"}`},
		{measurement.ExpectedTDX{}, ""},
		{measurement.ExpectedSEVSNP{}, ""},
		{nil, ""},
	} {
		got, err := json.Marshal(ExpectedFacts{CodeMeasurement: tc.code})
		require.NoError(t, err)
		var members map[string]jsontext.Value
		require.NoError(t, json.Unmarshal(got, &members))
		if tc.want == "" {
			require.NotContains(t, members, "code_measurement", "%v", tc.code)
			continue
		}
		require.JSONEq(t, tc.want, string(members["code_measurement"]))
	}
}

// The form's members and their presence: the schema version, exactly one of
// the facts, an established but empty fact kept, absent ones omitted, the
// verifier only for a release, and no null or "".
func TestReportJSONPresence(t *testing.T) {
	report := &VerificationReport{
		Steps:        []Step{{Layer: LayerEnvelope, Status: StepFailed, Message: "bad"}, {Layer: LayerProvenance, Status: StepNotRun}},
		PartialFacts: &PartialFacts{Measured: &MeasuredFacts{}},
		Metadata:     VerificationMetadata{Verifier: SoftwareIdentity{Name: sdkinfo.Name, Version: "0.17.0"}, VerifiedAt: goldenAt},
	}
	got, err := json.Marshal(report)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"schema_version": 1,
		"steps": [{"layer": "envelope", "status": "failed", "message": "bad"}, {"layer": "provenance", "status": "not_run"}],
		"partial_facts": {"measured": {}},
		"metadata": {"verified_at": "2026-01-02T02:04:05Z", "verifier": {"name": "tinfoil-go", "version": "0.17.0"}}
	}`, string(got))

	report.Metadata.Verifier.Version = "devel"
	report.Steps = nil
	report.PartialFacts = &PartialFacts{}
	got, err = json.Marshal(*report)
	require.NoError(t, err)
	require.JSONEq(t, `{"schema_version": 1, "steps": [], "partial_facts": {}, "metadata": {"verified_at": "2026-01-02T02:04:05Z"}}`, string(got))
	require.Equal(t, 1, ReportSchemaVersion)

	got, err = json.Marshal(&VerificationReport{VerifiedFacts: &VerifiedFacts{}})
	require.NoError(t, err)
	require.JSONEq(t, `{"schema_version": 1, "steps": [], "verified_facts": {"crypto_material": []}, "metadata": {}}`, string(got))

	got, err = json.Marshal((*VerificationReport)(nil))
	require.NoError(t, err)
	require.Equal(t, "null", string(got))
}

// The JSON form can't be read back into verified facts: they have no
// exported fields and no UnmarshalJSON, so decoding gives no key.
func TestVerifiedFactsCannotBeDecoded(t *testing.T) {
	encoded, err := json.Marshal(goldenConfigFacts())
	require.NoError(t, err)
	var facts VerifiedFacts
	_ = json.Unmarshal(encoded, &facts)
	_, ok := facts.TLSPublicKeyFP()
	require.False(t, ok)
	require.Empty(t, facts.CodeDigest())
}
