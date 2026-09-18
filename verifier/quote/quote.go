// Package quote verifies a v3 document's CPU evidence in three phases:
//
//  1. Authenticate: verify the quote's signature chain up to the pinned
//     vendor root, from document-carried collateral only. Authenticated,
//     not yet appraised.
//  2. Assemble: resolve the complete policy — every value the quote must
//     attest, as one object. Entries differ only in which verified source
//     resolves them (policy artifact, code provenance, envelope); that
//     distinction ends here. Assembly fails if any entry cannot be
//     resolved.
//  3. Validate: one comparison of the quote against the assembled policy,
//     inside the vendor library's validation options.
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

// registerSize is the byte length of every measurement register.
const registerSize = 48

// Authenticated is a signature-verified quote, not yet compared against
// any expected value.
type Authenticated struct {
	// Platform is policy.PlatformSEVSNP or policy.PlatformTDX.
	Platform string
	// Identity is the machine identifier from authenticated bytes
	// (SEV CHIP_ID / TDX PPID), lowercase hex.
	Identity string
	// Measurement is the launch measurement (SEV) or MRTD+RTMRs (TDX).
	Measurement *measurement.Measurement

	sev *sev.Quote
	tdx *tdx.Quote
}

// AssembledPolicy is the complete expected state of a quote, fully
// resolved before validation runs. It captures the quote it was assembled
// for, so it cannot be applied to any other quote.
type AssembledPolicy struct {
	// PolicyName is the matched policy name.
	PolicyName string
	// PlatformMeasurementName is the resolved TDX platform configuration;
	// empty for SEV-SNP.
	PlatformMeasurementName string

	quote *Authenticated
	sev   *sev.Expectations
	tdx   *tdx.Expectations
}

// Authenticate verifies the quote's signature chain up to the pinned
// vendor root, from the document's own endorsement collateral — no network
// fetches. Callers must assemble a policy and validate before trusting the
// platform.
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

// Assemble resolves the complete policy for an authenticated quote from
// its three verified sources: the policy artifact (machine lookup by
// authenticated identity; for TDX, the platform measurement resolved under
// the required VM shape), the code measurement, and the envelope's
// REPORT_DATA. A machine absent from the artifact is not endorsed.
func Assemble(endorsements *policy.Artifact, code *measurement.Measurement, shape *policy.Shape, reportData [64]byte, q *Authenticated) (*AssembledPolicy, error) {
	if code == nil {
		return nil, fmt.Errorf("assembling policy: expected code measurement is required")
	}
	if shape == nil {
		return nil, fmt.Errorf("assembling policy: the code artifact's VM shape is required")
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
		digest, err = sevLaunchDigest(code)
		if err == nil {
			assembled.sev, err = sev.Assemble(machinePolicy.SEVSNP, q.sev, digest, reportData)
		}
	case policy.PlatformTDX:
		var registers tdx.CodeRegisters
		registers, err = tdxCodeRegisters(code)
		if err == nil {
			assembled.tdx, assembled.PlatformMeasurementName, err = tdx.Assemble(
				endorsements, machinePolicy.TDX, shape, q.tdx, registers, reportData)
		}
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.Platform)
	}
	if err != nil {
		return nil, err
	}
	return assembled, nil
}

// Validate compares the captured quote against the assembled policy in a
// single vendor library call: no lookups, no translation.
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
func Verify(doc *envelope.Document, endorsements *policy.Artifact, code *measurement.Measurement, shape *policy.Shape, reportData [64]byte) (*AssembledPolicy, *Authenticated, error) {
	q, err := Authenticate(doc)
	if err != nil {
		return nil, nil, err
	}
	assembled, err := Assemble(endorsements, code, shape, reportData, q)
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
	case measurement.SnpTdxMultiPlatformV1:
		if len(m.Registers) != 3 {
			return nil, fmt.Errorf("multiplatform code measurement carries %d registers, want 3", len(m.Registers))
		}
		return decodeRegister(m.Registers[0])
	case measurement.SevGuestV2:
		if len(m.Registers) != 1 {
			return nil, fmt.Errorf("SEV code measurement carries %d registers, want 1", len(m.Registers))
		}
		return decodeRegister(m.Registers[0])
	default:
		return nil, fmt.Errorf("unsupported code measurement type %q for SEV-SNP", m.Type)
	}
}

// tdxCodeRegisters maps the expected code measurement onto the TDX
// workload registers.
func tdxCodeRegisters(m *measurement.Measurement) (code tdx.CodeRegisters, err error) {
	switch m.Type {
	case measurement.SnpTdxMultiPlatformV1:
		// Registers are [snp_measurement, rtmr1, rtmr2]; RTMR3 is never
		// measured and must be zero.
		if len(m.Registers) != 3 {
			return code, fmt.Errorf("multiplatform code measurement carries %d registers, want 3", len(m.Registers))
		}
		code.RTMR3 = make([]byte, registerSize)
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
	if len(b) != registerSize {
		return nil, fmt.Errorf("code measurement register must be %d bytes, got %d", registerSize, len(b))
	}
	return b, nil
}
