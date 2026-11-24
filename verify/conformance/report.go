//go:build tinfoil_conformance

package conformance

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

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
	if out.Accepted && out.Rejection != nil {
		return fmt.Errorf("an accepted verdict carries rejection %s", out.Rejection.Code)
	}
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
		if s.Layer != want[i] {
			return fmt.Errorf("step %d is %q, want %q", i, s.Layer, want[i])
		}
		switch {
		case failedAt >= 0:
			if s.Status != verify.StepNotRun {
				return fmt.Errorf("step %s after the failure is %q, want not_run", s.Layer, s.Status)
			}
		case s.Status == verify.StepFailed:
			failedAt = i
		case s.Status != verify.StepPassed && s.Status != verify.StepSkipped && s.Status != verify.StepNotRun:
			return fmt.Errorf("step %s has unknown status %q", s.Layer, s.Status)
		}
	}
	if out.Accepted {
		for _, s := range r.Steps {
			if s.Status != verify.StepPassed && s.Status != verify.StepSkipped {
				return fmt.Errorf("an accepted report has step %s %s", s.Layer, s.Status)
			}
		}
		if r.PartialFacts != nil {
			return fmt.Errorf("an accepted report has partial facts")
		}
		if r.VerifiedFacts == nil {
			return fmt.Errorf("an accepted report has no verified facts")
		}
		return nil
	}
	if out.Rejection == nil || failedAt < 0 {
		return fmt.Errorf("a rejection's report has no failed step")
	}
	if layer, ok := rejectionLayers[out.Rejection.Code]; !ok || want[failedAt] != layer {
		return fmt.Errorf("failed step %s does not match rejection code %s", want[failedAt], out.Rejection.Code)
	}
	if r.VerifiedFacts != nil {
		return fmt.Errorf("a rejection's report has verified facts")
	}
	p := r.PartialFacts
	if p == nil {
		return fmt.Errorf("a rejection's report has no partial facts")
	}
	ran := func(layer verify.Layer) bool {
		for _, s := range r.Steps {
			if s.Layer == layer {
				return s.Status == verify.StepPassed || s.Status == verify.StepSkipped
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
	if p.Measured != nil && (p.Measured.CPU != nil) != ran(verify.LayerQuote) {
		return fmt.Errorf("the CPU measurement is present=%v, but the quote step passed=%v", p.Measured.CPU != nil, ran(verify.LayerQuote))
	}
	if p.Expected != nil && p.Expected.Measurement != nil && want[failedAt] != verify.LayerPolicy {
		return fmt.Errorf("the full expected measurement is present before the policy step ran")
	}
	return nil
}
