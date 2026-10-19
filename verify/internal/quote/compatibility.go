package quote

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// CheckCompatibility appraises CPU policy without a client challenge. The
// quote's own REPORT_DATA is deliberately unconstrained, so this availability
// check cannot prove nonce, key, or device-evidence bindings.
func CheckCompatibility(refs ReferenceValues, pins *measurement.Measurement, q *Authenticated) (err error) {
	defer func() { err = errs.WrapVerification(err) }()
	if q == nil || q.sev == nil && q.tdx == nil {
		return &errs.UsageError{Err: fmt.Errorf("authenticated quote is required")}
	}
	var reportData [64]byte
	switch q.platform {
	case policy.PlatformSEVSNP:
		reportData = q.sev.ReportData()
	case policy.PlatformTDX:
		reportData = q.tdx.ReportData()
	default:
		return fmt.Errorf("unsupported platform %q", q.platform)
	}
	assembled, err := assemble(refs, pins, reportData, q)
	if err != nil {
		return err
	}
	return assembled.Validate()
}

// CheckRuntimeCompatibility excludes private config authorization and hash
// matching. It retains the quote's config hash only to exercise all remaining
// runtime and platform checks, including TDX's zero config-ID padding.
func CheckRuntimeCompatibility(platform *policy.Artifact, runtime *runtime.Measurements, pins *measurement.Measurement, q *Authenticated) error {
	if q == nil || q.sev == nil && q.tdx == nil {
		return errs.WrapVerification(fmt.Errorf("authenticated quote is required"))
	}
	refs := ConfigReferenceValues{Endorsements: platform, Runtime: runtime}
	switch q.platform {
	case policy.PlatformSEVSNP:
		refs.Hash = q.sev.ConfigHash()
	case policy.PlatformTDX:
		refs.Hash = q.tdx.ConfigHash()
	default:
		return errs.WrapVerification(fmt.Errorf("unsupported platform %q", q.platform))
	}
	return CheckCompatibility(refs, pins, q)
}
