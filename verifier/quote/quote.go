// Package quote verifies a v3 document's CPU evidence in three phases:
//
//  1. Authenticate: verify the quote's signature chain up to the pinned
//     vendor root, from document-carried collateral only. Authenticated,
//     not yet appraised.
//  2. Assemble: resolve the complete policy — every value the quote must
//     attest, as one object. Entries differ only in which verified source
//     resolves them (policy artifact, code provenance, document); that
//     distinction ends here. Assembly fails if any entry cannot be
//     resolved.
//  3. Validate: one comparison of the quote against the assembled policy,
//     inside the vendor library's validation options.
package quote

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/errs"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/tdx"
)

// Authenticated is a signature-verified quote, not yet compared against
// any expected value.
type Authenticated struct {
	platform string
	identity string
	// Measurement is a detached summary of the launch measurement (SEV) or MRTD+RTMRs (TDX).
	Measurement *measurement.Measurement

	sev *sev.Quote
	tdx *tdx.Quote
}

// Platform is policy.PlatformSEVSNP or policy.PlatformTDX.
func (q *Authenticated) Platform() string { return q.platform }

// Identity is the authenticated machine identifier (SEV CHIP_ID / TDX PPID), lowercase hex.
func (q *Authenticated) Identity() string { return q.identity }

// AssembledPolicy is the complete expected state of a quote, fully
// resolved before validation runs. It captures the quote it was assembled
// for, so it cannot be applied to any other quote.
type AssembledPolicy struct {
	// PolicyName is the matched policy name.
	PolicyName string
	// PlatformMeasurementName is the resolved TDX platform configuration;
	// empty for SEV-SNP.
	PlatformMeasurementName string

	quote Authenticated
	sev   *sev.Expectations
	tdx   *tdx.Expectations
}

// Authenticate verifies the quote's signature chain up to the pinned
// vendor root, from the document's own endorsement collateral — no network
// fetches. Callers must assemble a policy and validate before trusting the
// platform.
func Authenticate(doc *document.Document) (result *Authenticated, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if doc == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("document is required")}
	}
	switch doc.CPUEvidence.Format {
	case document.SEVSNPReportV1Format:
		q, err := sev.Authenticate(doc)
		if err != nil {
			return nil, err
		}
		return &Authenticated{
			platform:    policy.PlatformSEVSNP,
			identity:    q.Identity(),
			Measurement: q.Measurement,
			sev:         q,
		}, nil
	case document.TDXQuoteV1Format:
		q, err := tdx.Authenticate(doc)
		if err != nil {
			return nil, err
		}
		return &Authenticated{
			platform:    policy.PlatformTDX,
			identity:    q.Identity(),
			Measurement: q.Measurement,
			tdx:         q,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported cpu_evidence format %q", doc.CPUEvidence.Format)
	}
}

// Assemble combines endorsed machine policy, release measurements, caller pins,
// and REPORT_DATA. TDX platform measurements must match the required VM shape.
// A machine absent from endorsements is rejected. Pins fill unset registers or
// must match the existing source value.
func Assemble(endorsements *policy.Artifact, code, pins *measurement.Measurement, shape *policy.Shape, reportData [64]byte, q *Authenticated) (result *AssembledPolicy, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if endorsements == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("endorsements are required")}
	}
	if q == nil || q.sev == nil && q.tdx == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("authenticated quote is required")}
	}
	if code == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("assembling policy: expected code measurement is required")}
	}
	if q.platform == policy.PlatformTDX && shape == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("assembling policy: the code artifact's VM shape is required")}
	}
	name, machinePolicy, err := endorsements.PolicyFor(q.identity, q.platform)
	if err != nil {
		return nil, err
	}
	assembled := &AssembledPolicy{
		PolicyName: name,
		quote:      *q,
	}
	registers, err := layout(code, pins, q)
	if err != nil {
		return nil, err
	}
	switch q.platform {
	case policy.PlatformSEVSNP:
		assembled.sev, err = sev.Assemble(machinePolicy.SEVSNP, q.sev, registers[0], reportData)
	case policy.PlatformTDX:
		assembled.tdx, assembled.PlatformMeasurementName, err = tdx.Assemble(
			endorsements, machinePolicy.TDX, shape, q.tdx, [5]string(registers), reportData)
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.platform)
	}
	if err != nil {
		return nil, err
	}
	return assembled, nil
}

// Validate compares the captured quote against the assembled policy in a
// single vendor library call: no lookups, no translation.
func (p *AssembledPolicy) Validate() (err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if p == nil || p.sev == nil && p.tdx == nil {
		return &errs.ConfigurationError{Err: fmt.Errorf("assembled policy is required")}
	}
	switch p.quote.platform {
	case policy.PlatformSEVSNP:
		return p.sev.Validate(p.quote.sev)
	case policy.PlatformTDX:
		return p.tdx.Validate(p.quote.tdx)
	default:
		return fmt.Errorf("unsupported platform %q", p.quote.platform)
	}
}

// Verify composes Authenticate, Assemble, and Validate.
func Verify(doc *document.Document, endorsements *policy.Artifact, code, pins *measurement.Measurement, shape *policy.Shape, reportData [64]byte) (*AssembledPolicy, *Authenticated, error) {
	q, err := Authenticate(doc)
	if err != nil {
		return nil, nil, err
	}
	assembled, err := Assemble(endorsements, code, pins, shape, reportData, q)
	if err != nil {
		return nil, nil, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, nil, err
	}
	return assembled, q, nil
}

// layout maps code and pins to enclave registers, leaving platform defaults empty.
func layout(code, pins *measurement.Measurement, q *Authenticated) ([]string, error) {
	if err := measurement.ValidatePins(pins); err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	if code.Type != measurement.SnpTdxMultiPlatformV1 || len(code.Registers) != 3 {
		return nil, fmt.Errorf("code measurement is %s with %d registers, want %s with 3", code.Type, len(code.Registers), measurement.SnpTdxMultiPlatformV1)
	}
	registers := []string{code.Registers[0]}
	enclaveType := measurement.SevGuestV2
	if q.platform == policy.PlatformTDX {
		registers = []string{"", "", code.Registers[1], code.Registers[2], ""}
		enclaveType = measurement.TdxGuestV2
	}
	if pins == nil {
		return registers, nil
	}
	if pins.Type != enclaveType || len(pins.Registers) != len(registers) {
		return nil, fmt.Errorf("pinned measurement is %s with %d registers, enclave is %s with %d", pins.Type, len(pins.Registers), enclaveType, len(registers))
	}
	for i, pin := range pins.Registers {
		if pin != "" && registers[i] != "" && !strings.EqualFold(registers[i], pin) {
			return nil, fmt.Errorf("pinned register %d does not match the signed release measurement", i)
		}
		registers[i] = cmp.Or(registers[i], pin)
	}
	return registers, nil
}
