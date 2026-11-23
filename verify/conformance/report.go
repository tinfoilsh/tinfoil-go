//go:build tinfoil_conformance

package conformance

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Report is a verify.VerificationReport in the wire contract, for the
// full-verify stage: the outcome of each step, and on a rejection the facts
// that the steps before it established. Step messages are each SDK's own
// error text, so the wire carries only the layer and the status.
type Report struct {
	Steps        []ReportStep        `json:"steps"`
	PartialFacts *ReportPartialFacts `json:"partial_facts,omitempty"`
}

// ReportStep is one step: a layer ("envelope", "provenance", "quote" or
// "policy") and a status ("passed", "failed", "skipped" or "not_run").
type ReportStep struct {
	Layer  string `json:"layer"`
	Status string `json:"status"`
}

// ReportPartialFacts are what a rejected verification established. Expected
// is absent unless provenance passed or was skipped, and Measured unless the
// envelope passed.
type ReportPartialFacts struct {
	Expected *ReportExpectedFacts `json:"expected,omitempty"`
	Measured *ReportMeasuredFacts `json:"measured,omitempty"`
}

// ReportExpectedFacts are the accepted reference values. CodeMeasurement is
// for the platform that the document's evidence names, and Measurement, the
// full expectation, is present only once the policy step resolved it.
type ReportExpectedFacts struct {
	CodeDigest      string       `json:"code_digest,omitempty"`
	CodeMeasurement *Measurement `json:"code_measurement,omitempty"`
	Measurement     *Measurement `json:"measurement,omitempty"`
}

// ReportMeasuredFacts are what the document and its hardware claim.
// CPUMeasurement is present only once the quote step passed. The key
// fingerprints are unverified in a rejection; HPKEPublicKeyFP is the
// lowercase-hex SHA-256 of the HPKE key's bytes.
type ReportMeasuredFacts struct {
	CPUMeasurement  *Measurement `json:"cpu_measurement,omitempty"`
	TLSPublicKeyFP  string       `json:"tls_public_key_fp,omitempty"`
	HPKEPublicKeyFP string       `json:"hpke_public_key_fp,omitempty"`
}

// ReportOf lays out r for the wire, or returns nil for nil.
func ReportOf(r *verify.VerificationReport) *Report {
	if r == nil {
		return nil
	}
	out := &Report{Steps: make([]ReportStep, 0, len(r.Steps))}
	for _, s := range r.Steps {
		out.Steps = append(out.Steps, ReportStep{Layer: string(s.Layer), Status: string(s.Status)})
	}
	if p := r.PartialFacts; p != nil {
		out.PartialFacts = &ReportPartialFacts{}
		if e := p.Expected; e != nil {
			out.PartialFacts.Expected = &ReportExpectedFacts{
				CodeDigest: e.Artifact.Digest,
			}
			if e.CodeMeasurement != nil {
				code := ExpectedOf(e.CodeMeasurement)
				out.PartialFacts.Expected.CodeMeasurement = &code
			}
			if e.Measurement != nil {
				full := MeasurementOf(e.Measurement)
				out.PartialFacts.Expected.Measurement = &full
			}
		}
		if m := p.Measured; m != nil {
			out.PartialFacts.Measured = &ReportMeasuredFacts{TLSPublicKeyFP: m.TLSPublicKeyFP, HPKEPublicKeyFP: m.HPKEPublicKeyFP}
			if m.CPU != nil {
				cpu := MeasurementOf(m.CPU.Measurement)
				out.PartialFacts.Measured.CPUMeasurement = &cpu
			}
		}
	}
	return out
}

// FailedStep returns the layer of the step that failed, or "" if none did.
func (r *Report) FailedStep() string {
	if r == nil {
		return ""
	}
	for _, s := range r.Steps {
		if s.Status == string(verify.StepFailed) {
			return s.Layer
		}
	}
	return ""
}

// rejectionLayers maps a layer's rejection code to the layer.
var rejectionLayers = map[string]verify.Layer{
	"ENVELOPE_REJECTED":   verify.LayerEnvelope,
	"PROVENANCE_REJECTED": verify.LayerProvenance,
	"QUOTE_REJECTED":      verify.LayerQuote,
	"POLICY_REJECTED":     verify.LayerPolicy,
}

// CheckReport checks that a full-verify Output's report agrees with its
// verdict and keeps the report's rules: the four layers in order; on an
// accept, every step passed or was skipped and there are no partial facts;
// on a rejection, the failed step is the rejection code's layer, no step
// after it ran, and each partial fact is present only once the step that
// establishes it passed. A step before the failed one may be not_run, since
// checks don't always run in layer order.
func CheckReport(out Output) error {
	r := out.Report
	if out.Stage != StageVerify {
		if r != nil {
			return fmt.Errorf("stage %s carries a report", out.Stage)
		}
		return nil
	}
	if r == nil {
		// The adapter's own channel-key rule rejects a document that the
		// verifier accepted, and a malformed input never ran.
		if out.Rejection != nil && (out.Rejection.Code == "ENVELOPE_REJECTED" || out.Rejection.Code == "MALFORMED_INPUT") {
			return nil
		}
		return fmt.Errorf("verdict %+v has no report", out.Rejection)
	}
	want := []verify.Layer{verify.LayerEnvelope, verify.LayerProvenance, verify.LayerQuote, verify.LayerPolicy}
	if len(r.Steps) != len(want) {
		return fmt.Errorf("report has %d steps, want %d", len(r.Steps), len(want))
	}
	failedAt := -1
	for i, s := range r.Steps {
		if s.Layer != string(want[i]) {
			return fmt.Errorf("step %d is %q, want %q", i, s.Layer, want[i])
		}
		switch {
		case failedAt >= 0:
			if s.Status != string(verify.StepNotRun) {
				return fmt.Errorf("step %s after the failure is %q, want not_run", s.Layer, s.Status)
			}
		case s.Status == string(verify.StepFailed):
			failedAt = i
		case s.Status != string(verify.StepPassed) && s.Status != string(verify.StepSkipped) && s.Status != string(verify.StepNotRun):
			return fmt.Errorf("step %s has unknown status %q", s.Layer, s.Status)
		}
	}
	if out.Accepted {
		for _, s := range r.Steps {
			if s.Status != string(verify.StepPassed) && s.Status != string(verify.StepSkipped) {
				return fmt.Errorf("an accepted report has step %s %s", s.Layer, s.Status)
			}
		}
		if r.PartialFacts != nil {
			return fmt.Errorf("an accepted report has partial facts")
		}
		return nil
	}
	if out.Rejection == nil || failedAt < 0 {
		return fmt.Errorf("a rejection's report has no failed step")
	}
	if layer, ok := rejectionLayers[out.Rejection.Code]; !ok || want[failedAt] != layer {
		return fmt.Errorf("failed step %s does not match rejection code %s", want[failedAt], out.Rejection.Code)
	}
	p := r.PartialFacts
	if p == nil {
		return fmt.Errorf("a rejection's report has no partial facts")
	}
	ran := func(layer verify.Layer) bool {
		for _, s := range r.Steps {
			if s.Layer == string(layer) {
				return s.Status == string(verify.StepPassed) || s.Status == string(verify.StepSkipped)
			}
		}
		return false
	}
	if (p.Measured != nil) != ran(verify.LayerEnvelope) {
		return fmt.Errorf("measured facts present=%v, but the envelope step passed=%v", p.Measured != nil, ran(verify.LayerEnvelope))
	}
	if (p.Expected != nil) != ran(verify.LayerProvenance) {
		return fmt.Errorf("expected facts present=%v, but the provenance step passed=%v", p.Expected != nil, ran(verify.LayerProvenance))
	}
	if p.Measured != nil && (p.Measured.CPUMeasurement != nil) != ran(verify.LayerQuote) {
		return fmt.Errorf("the CPU measurement is present=%v, but the quote step passed=%v", p.Measured.CPUMeasurement != nil, ran(verify.LayerQuote))
	}
	if p.Expected != nil && p.Expected.Measurement != nil && want[failedAt] != verify.LayerPolicy {
		return fmt.Errorf("the full expected measurement is present before the policy step ran")
	}
	return nil
}
