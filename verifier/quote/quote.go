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
	"cmp"
	"fmt"
	"slices"
	"strings"

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

// Assemble resolves the complete policy for an authenticated quote from
// its three verified sources: the policy artifact (machine lookup by
// authenticated identity; for TDX, the platform measurement resolved under
// the required VM shape), the code measurement, and the envelope's
// REPORT_DATA. A machine absent from the artifact is not endorsed. A
// register set in expected fills an empty slot or must equal its source.
func Assemble(endorsements *policy.Artifact, code, expected *measurement.Measurement, shape *policy.Shape, reportData [64]byte, q *Authenticated) (*AssembledPolicy, error) {
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
	registers, err := layout(code, expected, q)
	if err != nil {
		return nil, err
	}
	switch q.platform {
	case policy.PlatformSEVSNP:
		var digest []byte
		digest, err = policy.DecodeHex("launch digest", registers[0], registerSize)
		if err == nil {
			assembled.sev, err = sev.Assemble(machinePolicy.SEVSNP, q.sev, digest, reportData)
		}
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
func Verify(doc *envelope.Document, endorsements *policy.Artifact, code, expected *measurement.Measurement, shape *policy.Shape, reportData [64]byte) (*AssembledPolicy, *Authenticated, error) {
	q, err := Authenticate(doc)
	if err != nil {
		return nil, nil, err
	}
	assembled, err := Assemble(endorsements, code, expected, shape, reportData, q)
	if err != nil {
		return nil, nil, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, nil, err
	}
	return assembled, q, nil
}

// layout lays code out in the enclave's registers, "" for platform-supplied ones, then applies pins.
func layout(code, expected *measurement.Measurement, q *Authenticated) ([]string, error) {
	var registers []string
	switch {
	case code.Type == measurement.SnpTdxMultiPlatformV1 && len(code.Registers) != 3:
		return nil, fmt.Errorf("multiplatform code measurement carries %d registers, want 3", len(code.Registers))
	case code.Type == measurement.SnpTdxMultiPlatformV1 && q.platform == policy.PlatformSEVSNP:
		registers = []string{code.Registers[0]}
	case code.Type == measurement.SnpTdxMultiPlatformV1:
		// Registers are [snp_measurement, rtmr1, rtmr2]; RTMR3 is never measured.
		registers = []string{"", "", code.Registers[1], code.Registers[2], ""}
	case code.Type != q.Measurement.Type:
		return nil, fmt.Errorf("unsupported code measurement type %q for %s", code.Type, q.platform)
	case len(code.Registers) != len(q.Measurement.Registers):
		return nil, fmt.Errorf("%s code measurement carries %d registers, want %d", q.platform, len(code.Registers), len(q.Measurement.Registers))
	case q.platform == policy.PlatformTDX:
		// Registers are [mrtd, rtmr0, rtmr1, rtmr2, rtmr3].
		registers = append([]string{"", ""}, code.Registers[2:]...)
	default:
		registers = slices.Clone(code.Registers)
	}
	if expected == nil {
		return registers, nil
	}
	if expected.Type != q.Measurement.Type || len(expected.Registers) != len(registers) {
		return nil, fmt.Errorf("expected measurement is %s with %d registers, enclave is %s with %d", expected.Type, len(expected.Registers), q.Measurement.Type, len(registers))
	}
	for i, pin := range expected.Registers {
		if pin != "" && registers[i] != "" && !strings.EqualFold(registers[i], pin) {
			return nil, fmt.Errorf("register %d pinned to %s, release measures %s", i, pin, registers[i])
		}
		registers[i] = cmp.Or(registers[i], pin)
	}
	return registers, nil
}
