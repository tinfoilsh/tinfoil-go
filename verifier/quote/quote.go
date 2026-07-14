// Package quote verifies a v3 document's CPU evidence in three phases with
// an explicit trust state between each:
//
//  1. Authenticate: verify the quote's signature chain up to the pinned
//     vendor root, using only endorsement collateral carried in the
//     document. The result is authenticated but not yet appraised.
//  2. Assemble: resolve the complete expected state of the quote from
//     verified reference values — the endorsed machine policy, the platform
//     measurement selection, the expected launch registers from code
//     provenance, and the expected REPORT_DATA from the envelope. Nothing
//     is deferred to a later check.
//  3. Validate: compare the quote against the assembled policy in a single
//     call. Every register comparison happens inside the vendor library's
//     validation options.
package quote

import (
	"encoding/hex"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/tdx"
)

// Authenticated holds a quote whose signature chain has been verified up to
// the pinned vendor root. Nothing in it has been compared against expected
// values yet: that is the assembled policy's job.
type Authenticated struct {
	// Platform is policy.PlatformSEVSNP or policy.PlatformTDX.
	Platform string
	// Identity is the machine identifier from authenticated bytes
	// (SEV CHIP_ID / TDX PPID from the PCK leaf), lowercase hex.
	Identity string
	// Measurement is the launch measurement (SEV) or MRTD+RTMRs (TDX).
	Measurement *measurement.Measurement

	sev *sev.Quote
	tdx *tdx.Quote
}

// Expected carries the expected quote state resolved from sources other
// than the platform-endorsements artifact: the envelope and verified code
// provenance.
type Expected struct {
	// ReportData is the expected REPORT_DATA recomputed from the envelope.
	ReportData [64]byte
	// CodeMeasurement is the expected launch measurement from verified code
	// provenance. Required.
	CodeMeasurement *measurement.Measurement
	// Shape is the VM shape the code artifact declares; nil when the
	// artifact predates the vm_shape declaration.
	Shape *policy.Shape
}

// AssembledPolicy is the complete expected state of a quote — every value
// validation compares against, fully resolved from verified reference
// values before validation runs. It captures the authenticated quote it was
// assembled for, so it cannot be applied to any other quote.
type AssembledPolicy struct {
	// PolicyName is the matched appraisal policy name.
	PolicyName string
	// PlatformMeasurementName names the endorsed TDX platform configuration
	// the quote resolved to; empty for SEV-SNP.
	PlatformMeasurementName string

	quote *Authenticated
	sev   *sev.Expectations
	tdx   *tdx.Expectations
}

// Authenticate verifies a v3 document's CPU quote: the signature chain up
// to the pinned vendor root, using the endorsement collateral (VCEK / Intel
// PCS captures) carried in the document itself — authentication is
// single-request and performs no network fetches. It makes no
// reference-value comparison; callers must assemble a policy and validate
// before trusting the platform.
func Authenticate(doc *envelope.Document) (*Authenticated, error) {
	switch doc.CPUEvidence.Format {
	case envelope.SEVSNPReportV1Format:
		q, err := sev.Authenticate(doc)
		if err != nil {
			return nil, err
		}
		return &Authenticated{
			Platform:    policy.PlatformSEVSNP,
			Identity:    q.Identity,
			Measurement: q.Measurement,
			sev:         q,
		}, nil
	case envelope.TDXQuoteV1Format:
		q, err := tdx.Authenticate(doc)
		if err != nil {
			return nil, err
		}
		return &Authenticated{
			Platform:    policy.PlatformTDX,
			Identity:    q.Identity,
			Measurement: q.Measurement,
			tdx:         q,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported cpu_evidence format %q", doc.CPUEvidence.Format)
	}
}

// Assemble resolves the complete expected state of an authenticated quote:
// the machines-map lookup keyed by the authenticated platform identity (a
// machine absent from the map is not endorsed), the machine policy fully
// translated into vendor library validation options — carrying the expected
// launch registers from code provenance, the expected REPORT_DATA from the
// envelope, and for TDX the platform measurement resolved under the
// required VM shape. Assembly fails when any required value cannot be
// resolved; nothing is deferred to a later check.
func Assemble(endorsements *policy.Artifact, expected Expected, q *Authenticated) (*AssembledPolicy, error) {
	if expected.CodeMeasurement == nil {
		return nil, fmt.Errorf("assembling policy: expected code measurement is required")
	}
	name, machinePolicy, err := endorsements.PolicyFor(q.Identity, q.Platform)
	if err != nil {
		return nil, err
	}
	assembled := &AssembledPolicy{
		PolicyName: name,
		quote:      q,
	}
	switch q.Platform {
	case policy.PlatformSEVSNP:
		var digest []byte
		digest, err = sevLaunchDigest(expected.CodeMeasurement)
		if err == nil {
			assembled.sev, err = sev.Assemble(machinePolicy.SEVSNP, q.sev.ProductLine(), digest, expected.ReportData)
		}
	case policy.PlatformTDX:
		var code tdx.CodeRegisters
		code, err = tdxCodeRegisters(expected.CodeMeasurement)
		if err == nil {
			assembled.tdx, assembled.PlatformMeasurementName, err = tdx.Assemble(
				endorsements, machinePolicy.TDX, expected.Shape, q.tdx, code, expected.ReportData)
		}
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.Platform)
	}
	if err != nil {
		return nil, err
	}
	return assembled, nil
}

// Validate compares the captured authenticated quote against the assembled
// policy in a single vendor library call. It performs no lookups, no
// translation, and no recomputation.
func (p *AssembledPolicy) Validate() error {
	switch p.quote.Platform {
	case policy.PlatformSEVSNP:
		return p.sev.Validate(p.quote.sev)
	case policy.PlatformTDX:
		return p.tdx.Validate(p.quote.tdx)
	default:
		return fmt.Errorf("unsupported platform %q", p.quote.Platform)
	}
}

// Verify composes Authenticate, Assemble, and Validate.
func Verify(doc *envelope.Document, expected Expected, endorsements *policy.Artifact) (*AssembledPolicy, *Authenticated, error) {
	q, err := Authenticate(doc)
	if err != nil {
		return nil, nil, err
	}
	assembled, err := Assemble(endorsements, expected, q)
	if err != nil {
		return nil, nil, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, nil, err
	}
	return assembled, q, nil
}

// sevLaunchDigest maps the expected code measurement onto the SEV launch
// digest register.
func sevLaunchDigest(m *measurement.Measurement) ([]byte, error) {
	switch m.Type {
	case measurement.SnpTdxMultiPlatformV1, measurement.SevGuestV2:
		if len(m.Registers) < 1 {
			return nil, fmt.Errorf("code measurement carries no registers")
		}
		return decodeRegister(m.Registers[0])
	default:
		return nil, fmt.Errorf("unsupported code measurement type %q for SEV-SNP", m.Type)
	}
}

// tdxCodeRegisters maps the expected code measurement onto the TDX workload
// registers, decoding the predicate's positional register layout.
func tdxCodeRegisters(m *measurement.Measurement) (code tdx.CodeRegisters, err error) {
	switch m.Type {
	case measurement.SnpTdxMultiPlatformV1:
		// Registers are [snp_measurement, rtmr1, rtmr2]; RTMR3 is never
		// measured and must be zero.
		if len(m.Registers) != 3 {
			return code, fmt.Errorf("multiplatform code measurement carries %d registers, want 3", len(m.Registers))
		}
		code.RTMR3 = make([]byte, 48)
		if code.RTMR1, err = decodeRegister(m.Registers[1]); err != nil {
			return code, err
		}
		code.RTMR2, err = decodeRegister(m.Registers[2])
		return code, err
	case measurement.TdxGuestV2:
		// Registers are [mrtd, rtmr0, rtmr1, rtmr2, rtmr3].
		if len(m.Registers) != 5 {
			return code, fmt.Errorf("TDX code measurement carries %d registers, want 5", len(m.Registers))
		}
		if code.RTMR1, err = decodeRegister(m.Registers[2]); err != nil {
			return code, err
		}
		if code.RTMR2, err = decodeRegister(m.Registers[3]); err != nil {
			return code, err
		}
		code.RTMR3, err = decodeRegister(m.Registers[4])
		return code, err
	default:
		return code, fmt.Errorf("unsupported code measurement type %q for TDX", m.Type)
	}
}

// decodeRegister decodes a 48-byte hex measurement register.
func decodeRegister(hexValue string) ([]byte, error) {
	b, err := hex.DecodeString(hexValue)
	if err != nil {
		return nil, fmt.Errorf("code measurement register is not hex: %w", err)
	}
	if len(b) != 48 {
		return nil, fmt.Errorf("code measurement register must be 48 bytes, got %d", len(b))
	}
	return b, nil
}
