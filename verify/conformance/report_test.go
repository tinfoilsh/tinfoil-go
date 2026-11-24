//go:build tinfoil_conformance

package conformance

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// verifyVector runs the full-verify vector at path, under the conformance
// suite's vectors directory, through the verifier.
func verifyVector(t *testing.T, path string) (*verify.VerificationReport, error) {
	t.Helper()
	dir := os.Getenv("TINFOIL_CONFORMANCE_VECTORS")
	if dir == "" {
		t.Skip("set TINFOIL_CONFORMANCE_VECTORS to the conformance suite's vectors directory")
	}
	data, err := os.ReadFile(filepath.Join(dir, path))
	require.NoError(t, err)
	var f fixture
	require.NoError(t, json.Unmarshal(data, &f))
	require.Equal(t, StageVerify, f.Stage)
	sigstore, amd, intel, err := f.Input.TrustAnchors()
	require.NoError(t, err)
	verifier, err := verify.DangerousTestOnlyNewVerifier(nil, verify.Policy{}, verify.DangerousTestOnlyRoots{SigstoreRootJSON: sigstore, AMDRootPEM: amd, IntelRootPEM: intel})
	require.NoError(t, err)
	doc, err := base64.StdEncoding.DecodeString(f.Input.DocumentB64)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(f.Input.NonceHex)
	require.NoError(t, err)
	// As in Run, a vector without a verification time is appraised now.
	at := time.Now()
	if f.Input.VerificationTimeUnix != 0 {
		at = time.Unix(f.Input.VerificationTimeUnix, 0)
	}
	return verifier.VerifyV3At(doc, nonce, verify.Pin{Repo: f.Input.Repo, Project: f.Input.Project}, at)
}

func statuses(r *verify.VerificationReport) []verify.StepStatus {
	var out []verify.StepStatus
	for _, s := range r.Steps {
		out = append(out, s.Status)
	}
	return out
}

func rejectedReport(t *testing.T, err error, layer verify.Layer) *verify.VerificationReport {
	t.Helper()
	var rejected *verify.VerificationError
	require.True(t, errors.As(err, &rejected), "%v", err)
	require.Equal(t, layer, rejected.Layer)
	require.NotNil(t, rejected.Report)
	require.Nil(t, rejected.Report.VerifiedFacts)
	require.NotNil(t, rejected.Report.PartialFacts)
	failed, ok := rejected.Report.Failed()
	require.True(t, ok)
	require.Equal(t, layer, failed.Layer)
	require.Equal(t, rejected.Err.Error(), failed.Message)
	return rejected.Report
}

var (
	passed  = verify.StepPassed
	failed  = verify.StepFailed
	notRun  = verify.StepNotRun
	allPass = []verify.StepStatus{passed, passed, passed, passed}
)

func TestReportOfAnAcceptedVector(t *testing.T) {
	report, err := verifyVector(t, "v3/golden/golden-happy.json")
	require.NoError(t, err)
	assert.Equal(t, allPass, statuses(report))
	assert.Nil(t, report.PartialFacts)
	require.NotNil(t, report.VerifiedFacts)
	_, ok := report.VerifiedFacts.HPKEPublicKey()
	assert.True(t, ok)
	assert.Equal(t, time.UTC, report.Metadata.VerifiedAt.Location())
}

func TestReportOfAnEnvelopeRejectionVector(t *testing.T) {
	_, err := verifyVector(t, "v3/freshness/fr1-nonce-stale.json")
	report := rejectedReport(t, err, verify.LayerEnvelope)
	assert.Equal(t, []verify.StepStatus{failed, notRun, notRun, notRun}, statuses(report))
	assert.Nil(t, report.PartialFacts.Expected)
	assert.Nil(t, report.PartialFacts.Measured)
}

func TestReportOfAProvenanceRejectionVector(t *testing.T) {
	_, err := verifyVector(t, "v3/freshness/fr2-stale.json")
	report := rejectedReport(t, err, verify.LayerProvenance)
	assert.Equal(t, []verify.StepStatus{passed, failed, notRun, notRun}, statuses(report))
	assert.Nil(t, report.PartialFacts.Expected)
	measured := report.PartialFacts.Measured
	require.NotNil(t, measured)
	assert.Nil(t, measured.CPU)
	assert.Len(t, measured.TLSPublicKeyFP, 64)
	assert.Len(t, measured.HPKEPublicKeyFP, 64)
}

// A launch measurement that the release doesn't fix fails the policy step
// with both sides of the comparison in the report.
func TestReportOfAMeasurementMismatchVector(t *testing.T) {
	_, err := verifyVector(t, "v3/golden/s14-measurement.json")
	report := rejectedReport(t, err, verify.LayerPolicy)
	assert.Equal(t, []verify.StepStatus{passed, passed, passed, failed}, statuses(report))
	expected := report.PartialFacts.Expected
	require.NotNil(t, expected)
	assert.NotEmpty(t, expected.Artifact.Digest)
	assert.Equal(t, expected.Artifact.Repo, expected.ConfigRepo)
	code, ok := expected.CodeMeasurement.(measurement.ExpectedSEVSNP)
	require.True(t, ok)
	full, ok := expected.Measurement.(measurement.SEVSNP)
	require.True(t, ok, "the policy step resolved the expectation before it compared")
	assert.Equal(t, *code.Launch, full.Launch)
	measured := report.PartialFacts.Measured
	require.NotNil(t, measured.CPU)
	assert.NotEqual(t, full, measured.CPU.Measurement)
}

// For a code release on TDX, the full expectation adds the platform
// registers that the platform endorsements resolve for the quote's machine.
func TestReportOfATDXRegisterMismatchVector(t *testing.T) {
	_, err := verifyVector(t, "v3/golden-tdx/t18-rtmr1.json")
	report := rejectedReport(t, err, verify.LayerPolicy)
	expected := report.PartialFacts.Expected
	code := expected.CodeMeasurement.(measurement.ExpectedTDX)
	assert.Nil(t, code.MRTD, "the release leaves MRTD to the platform")
	full, ok := expected.Measurement.(measurement.TDX)
	require.True(t, ok)
	cpu := report.PartialFacts.Measured.CPU.Measurement.(measurement.TDX)
	assert.Equal(t, cpu.MRTD, full.MRTD, "the platform endorses the machine's MRTD")
	assert.Equal(t, cpu.RTMR0, full.RTMR0)
	assert.Equal(t, *code.RTMR1, full.RTMR1)
	assert.NotEqual(t, cpu.RTMR1, full.RTMR1)

	// A platform register that no endorsement resolves fails the policy
	// step before the expectation is complete.
	_, err = verifyVector(t, "v3/golden-tdx/t17-rtmr0.json")
	report = rejectedReport(t, err, verify.LayerPolicy)
	assert.Nil(t, report.PartialFacts.Expected.Measurement)
	assert.NotNil(t, report.PartialFacts.Expected.CodeMeasurement)
	assert.NotNil(t, report.PartialFacts.Measured.CPU)
}

func TestCheckReportRejectsInconsistentReports(t *testing.T) {
	steps := func(statuses ...verify.StepStatus) []verify.Step {
		layers := []verify.Layer{verify.LayerEnvelope, verify.LayerProvenance, verify.LayerQuote, verify.LayerPolicy}
		out := make([]verify.Step, len(statuses))
		for i, s := range statuses {
			out[i] = verify.Step{Layer: layers[i], Status: s}
		}
		return out
	}
	measured := &verify.MeasuredFacts{TLSPublicKeyFP: strings.Repeat("a", 64)}
	ok := Output{Stage: StageVerify, Rejection: &Rejection{Code: "PROVENANCE_REJECTED"}, Report: &verify.VerificationReport{
		Steps:        steps(passed, failed, notRun, notRun),
		PartialFacts: &verify.PartialFacts{Measured: measured},
	}}
	require.NoError(t, CheckReport(ok))
	for name, mutate := range map[string]func(*Output){
		"wrong layer":      func(o *Output) { o.Rejection.Code = "QUOTE_REJECTED" },
		"ran after":        func(o *Output) { o.Report.Steps[2].Status = passed },
		"expected early":   func(o *Output) { o.Report.PartialFacts.Expected = &verify.ExpectedFacts{} },
		"no measured":      func(o *Output) { o.Report.PartialFacts.Measured = nil },
		"cpu early":        func(o *Output) { o.Report.PartialFacts.Measured.CPU = &verify.CPUEvidence{} },
		"three steps":      func(o *Output) { o.Report.Steps = o.Report.Steps[:3] },
		"no partial facts": func(o *Output) { o.Report.PartialFacts = nil },
		"verified facts":   func(o *Output) { o.Report.VerifiedFacts = &verify.VerifiedFacts{} },
		"accepted":         func(o *Output) { o.Accepted = true },
	} {
		o := ok
		o.Report = ok.Report.Clone()
		rejection := *ok.Rejection
		o.Rejection = &rejection
		mutate(&o)
		assert.Error(t, CheckReport(o), name)
	}
}
