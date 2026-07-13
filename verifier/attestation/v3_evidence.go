package attestation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// ErrCollateralNotFound reports that a document carries no collateral entry
// of the requested role and format.
var ErrCollateralNotFound = errors.New("collateral entry not found")

// EvidenceV3 is the result of verifying a v3 document's CPU evidence: the
// authenticated platform facts a caller may rely on after verification.
type EvidenceV3 struct {
	// Platform is policy.PlatformSEVSNP or policy.PlatformTDX.
	Platform string
	// PlatformIdentity is the endorsed machine identifier extracted from
	// authenticated evidence (SEV CHIP_ID / TDX PPID), lowercase hex.
	PlatformIdentity string
	// PolicyName is the appraisal policy the machine is endorsed with.
	PolicyName string
	// Measurement carries the launch measurement (SEV) or MRTD+RTMRs (TDX).
	Measurement *Measurement
}

// AuthenticatedQuote holds the quote fields authenticated by
// AuthenticateQuoteV3. Nothing in it has been compared against expected
// values yet: that is ValidateQuoteV3's job.
type AuthenticatedQuote struct {
	// Platform is policy.PlatformSEVSNP or policy.PlatformTDX.
	Platform string
	// PlatformIdentity is the machine identifier from authenticated bytes
	// (SEV CHIP_ID / TDX PPID from the PCK leaf), lowercase hex.
	PlatformIdentity string
	// Measurement is the launch measurement (SEV) or MRTD+RTMRs (TDX).
	Measurement *Measurement

	reportData []byte
	sev        *sevsnp.Attestation
	tdx        *tdxpb.QuoteV4
	// tdxTCBEvaluationDataNumber is the minimum tcbEvaluationDataNumber
	// observed in the verified Intel collateral.
	tdxTCBEvaluationDataNumber int
}

// ExpectedValues carries the expected quote state resolved from sources
// other than the platform-endorsements artifact: the envelope and verified
// code provenance. Both are required.
type ExpectedValues struct {
	// ReportData is the expected REPORT_DATA from the envelope.
	ReportData [64]byte
	// CodeMeasurement is the expected launch measurement from verified code
	// provenance.
	CodeMeasurement *Measurement
}

// AssembledPolicy is the complete expected state of a quote — every value
// validation compares against, fully resolved from verified reference
// values before validation runs. It is bound to the authenticated quote it
// was assembled for: validation rejects any other quote.
type AssembledPolicy struct {
	// PolicyName is the matched appraisal policy name.
	PolicyName string
	// Expected carries the envelope and code-provenance expectations.
	Expected ExpectedValues

	platform         string
	platformIdentity string
	sev              *policy.SEVExpectations
	tdx              *policy.TDXExpectations
}

// AuthenticateQuoteV3 authenticates a v3 document's CPU quote: the
// signature chain up to the pinned vendor roots, using the endorsement
// collateral (VCEK / Intel PCS captures) carried in the document itself —
// authentication is single-request and performs no network fetches. It
// makes no reference-value comparison; callers must assemble a policy and
// run ValidateQuoteV3 before trusting the platform.
func AuthenticateQuoteV3(doc *DocumentV3) (*AuthenticatedQuote, error) {
	switch doc.CPUEvidence.Format {
	case SEVSNPReportV1Format:
		return authenticateSevQuoteV3(doc)
	case TDXQuoteV1Format:
		return authenticateTdxQuoteV3(doc)
	default:
		return nil, fmt.Errorf("unsupported cpu_evidence format %q", doc.CPUEvidence.Format)
	}
}

// AssemblePolicyV3 resolves the complete expected state of an authenticated
// quote: the machines-map lookup keyed by the authenticated platform
// identity (a machine absent from the map is not endorsed), the machine
// policy fully translated into platform expectations, plus the expected
// values from the envelope and code provenance. Assembly fails when any
// required value cannot be resolved; nothing is deferred to a later check.
func AssemblePolicyV3(endorsements *policy.Artifact, expected ExpectedValues, quote *AuthenticatedQuote) (*AssembledPolicy, error) {
	if expected.CodeMeasurement == nil {
		return nil, fmt.Errorf("assembling policy: expected code measurement is required")
	}
	name, machinePolicy, err := endorsements.PolicyFor(quote.PlatformIdentity, quote.Platform)
	if err != nil {
		return nil, err
	}
	assembled := &AssembledPolicy{
		PolicyName:       name,
		Expected:         expected,
		platform:         quote.Platform,
		platformIdentity: quote.PlatformIdentity,
	}
	switch quote.Platform {
	case policy.PlatformSEVSNP:
		var digest []byte
		digest, err = sevLaunchDigest(expected.CodeMeasurement)
		if err == nil {
			assembled.sev, err = machinePolicy.SEVSNP.AssembleSEV(kds.ProductLine(quote.sev.GetProduct()), digest)
		}
	case policy.PlatformTDX:
		var code policy.TDXCodeRegisters
		code, err = tdxCodeRegisters(expected.CodeMeasurement)
		if err == nil {
			assembled.tdx, err = endorsements.AssembleTDX(machinePolicy.TDX, quote.tdx, code)
		}
	default:
		return nil, fmt.Errorf("unsupported platform %q", quote.Platform)
	}
	if err != nil {
		return nil, err
	}
	return assembled, nil
}

// sevLaunchDigest maps the expected code measurement onto the SEV launch
// digest register.
func sevLaunchDigest(m *Measurement) ([]byte, error) {
	switch m.Type {
	case SnpTdxMultiPlatformV1, SevGuestV2:
		if len(m.Registers) < 1 {
			return nil, fmt.Errorf("code measurement carries no registers")
		}
		return decodeRegister(m.Registers[0])
	default:
		return nil, fmt.Errorf("unsupported code measurement type %q for SEV-SNP", m.Type)
	}
}

// tdxCodeRegisters maps the expected code measurement onto the TDX workload
// registers. RTMR3 is unmeasured and must be zero.
func tdxCodeRegisters(m *Measurement) (policy.TDXCodeRegisters, error) {
	var indices [3]int
	switch m.Type {
	case SnpTdxMultiPlatformV1:
		// Registers are [snp_measurement, rtmr1, rtmr2].
		indices = [3]int{1, 2, -1}
	case TdxGuestV2:
		// Registers are [mrtd, rtmr0, rtmr1, rtmr2, rtmr3].
		indices = [3]int{2, 3, 4}
	default:
		return policy.TDXCodeRegisters{}, fmt.Errorf("unsupported code measurement type %q for TDX", m.Type)
	}

	registers := [3][]byte{}
	for i, idx := range indices {
		if idx < 0 {
			registers[i] = make([]byte, 48)
			continue
		}
		if idx >= len(m.Registers) {
			return policy.TDXCodeRegisters{}, fmt.Errorf("code measurement carries %d registers, need %d", len(m.Registers), idx+1)
		}
		reg, err := decodeRegister(m.Registers[idx])
		if err != nil {
			return policy.TDXCodeRegisters{}, err
		}
		registers[i] = reg
	}
	return policy.TDXCodeRegisters{RTMR1: registers[0], RTMR2: registers[1], RTMR3: registers[2]}, nil
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

// ValidateQuoteV3 compares an authenticated quote against an assembled
// policy: REPORT_DATA equality and the platform expectations, which include
// the expected launch measurement. It performs no lookups, no translation,
// and no recomputation.
func ValidateQuoteV3(quote *AuthenticatedQuote, assembled *AssembledPolicy) error {
	if quote.Platform != assembled.platform || quote.PlatformIdentity != assembled.platformIdentity {
		return fmt.Errorf("assembled policy does not correspond to the authenticated quote")
	}
	if !bytes.Equal(quote.reportData, assembled.Expected.ReportData[:]) {
		return fmt.Errorf("quote REPORT_DATA does not match the recomputed value")
	}

	switch quote.Platform {
	case policy.PlatformSEVSNP:
		return assembled.sev.Validate(quote.sev)
	case policy.PlatformTDX:
		return assembled.tdx.Validate(quote.tdx, quote.tdxTCBEvaluationDataNumber)
	default:
		return fmt.Errorf("unsupported platform %q", quote.Platform)
	}
}

// VerifyCPUEvidenceV3 composes AuthenticateQuoteV3, AssemblePolicyV3, and
// ValidateQuoteV3.
func VerifyCPUEvidenceV3(doc *DocumentV3, expected ExpectedValues, endorsements *policy.Artifact) (*EvidenceV3, error) {
	quote, err := AuthenticateQuoteV3(doc)
	if err != nil {
		return nil, err
	}
	assembled, err := AssemblePolicyV3(endorsements, expected, quote)
	if err != nil {
		return nil, err
	}
	if err := ValidateQuoteV3(quote, assembled); err != nil {
		return nil, err
	}
	return &EvidenceV3{
		Platform:         quote.Platform,
		PlatformIdentity: quote.PlatformIdentity,
		PolicyName:       assembled.PolicyName,
		Measurement:      quote.Measurement,
	}, nil
}

// endorsementCollateral returns the first endorsement-role collateral entry
// with the given format whose subjects include subject.
func (d *DocumentV3) endorsementCollateral(format, subject string) (*CollateralEntry, bool) {
	for i := range d.Collateral {
		entry := &d.Collateral[i]
		if entry.Role != RoleEndorsement || entry.Format != format {
			continue
		}
		for _, s := range entry.Subjects {
			if s == subject {
				return entry, true
			}
		}
	}
	return nil, false
}

// ReferenceValuesCollateral returns the first reference-values collateral
// entry with the given format, parsed as a Sigstore collateral payload. A
// document without such an entry returns an error wrapping
// ErrCollateralNotFound.
func (d *DocumentV3) ReferenceValuesCollateral(format string) (*SigstoreCollateral, error) {
	for i := range d.Collateral {
		entry := &d.Collateral[i]
		if entry.Role != RoleReferenceValues || entry.Format != format {
			continue
		}
		var sc SigstoreCollateral
		if err := strictUnmarshal(entry.Data, &sc); err != nil {
			return nil, fmt.Errorf("parsing %s collateral entry %q: %w", format, entry.ID, err)
		}
		return &sc, nil
	}
	return nil, fmt.Errorf("%w: document carries no %s reference-values entry", ErrCollateralNotFound, format)
}
