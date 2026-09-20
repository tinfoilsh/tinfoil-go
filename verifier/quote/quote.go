// Package quote authenticates CPU evidence using document-carried collateral and
// pinned vendor roots. It then assembles and checks expectations from platform
// policy, code measurements, caller pins, and REPORT_DATA.
package quote

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
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

// AssembledPolicy holds the policy checks and a copy of the authenticated quote
// to which they apply.
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

// Authenticate verifies the quote's signature chain against the pinned vendor
// root using document-carried collateral. Callers must also assemble and validate
// a policy before trusting the platform. No network requests are made.
func Authenticate(doc *envelope.Document) (*Authenticated, error) {
	switch doc.CPUEvidence.Format {
	case envelope.SEVSNPReportV1Format:
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
	case envelope.TDXQuoteV1Format:
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
func Assemble(endorsements *policy.Artifact, code, pins *measurement.Measurement, shape *policy.Shape, reportData [64]byte, q *Authenticated) (*AssembledPolicy, error) {
	if code == nil {
		return nil, fmt.Errorf("assembling policy: expected code measurement is required")
	}
	if shape == nil {
		return nil, fmt.Errorf("assembling policy: the code artifact's VM shape is required")
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

// Validate checks the captured quote against the assembled policy.
func (p *AssembledPolicy) Validate() error {
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
func Verify(doc *envelope.Document, endorsements *policy.Artifact, code, pins *measurement.Measurement, shape *policy.Shape, reportData [64]byte) (*AssembledPolicy, *Authenticated, error) {
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
	if code.Type != measurement.SnpTdxMultiPlatformV1 || len(code.Registers) != 3 {
		return nil, fmt.Errorf("code measurement is %s with %d registers, want %s with 3", code.Type, len(code.Registers), measurement.SnpTdxMultiPlatformV1)
	}
	// Registers are [snp_measurement, rtmr1, rtmr2].
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
			return nil, fmt.Errorf("register %d pinned to %s, release measures %s", i, pin, registers[i])
		}
		registers[i] = cmp.Or(registers[i], pin)
	}
	return registers, nil
}
