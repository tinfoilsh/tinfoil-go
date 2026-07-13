package attestation

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
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
// code provenance.
type ExpectedValues struct {
	// ReportData is the expected REPORT_DATA from the envelope.
	ReportData [64]byte
	// CodeMeasurement is the expected launch measurement from verified code
	// provenance. When nil, the launch-measurement comparison is skipped and
	// the caller is responsible for it.
	CodeMeasurement *Measurement
}

// AssembledPolicy is the complete expected state of a quote, resolved from
// verified reference values before validation runs.
type AssembledPolicy struct {
	// PolicyName is the matched appraisal policy name.
	PolicyName string
	// Expected carries the envelope and code-provenance expectations.
	Expected ExpectedValues

	artifact *policy.Artifact
	machine  *policy.Policy
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
// identity (a machine absent from the map is not endorsed), plus the
// expected values from the envelope and code provenance.
func AssemblePolicyV3(endorsements *policy.Artifact, expected ExpectedValues, quote *AuthenticatedQuote) (*AssembledPolicy, error) {
	name, machinePolicy, err := endorsements.PolicyFor(quote.PlatformIdentity, quote.Platform)
	if err != nil {
		return nil, err
	}
	return &AssembledPolicy{
		PolicyName: name,
		Expected:   expected,
		artifact:   endorsements,
		machine:    machinePolicy,
	}, nil
}

// ValidateQuoteV3 compares an authenticated quote against an assembled
// policy: REPORT_DATA equality, the platform policy block, and (when
// present) the expected launch measurement. It performs no lookups and no
// recomputation.
func ValidateQuoteV3(quote *AuthenticatedQuote, assembled *AssembledPolicy) error {
	if !bytes.Equal(quote.reportData, assembled.Expected.ReportData[:]) {
		return fmt.Errorf("quote REPORT_DATA does not match the recomputed value")
	}

	switch quote.Platform {
	case policy.PlatformSEVSNP:
		productLine := kds.ProductLine(quote.sev.GetProduct())
		valOpts, err := assembled.machine.SEVSNP.SEVOptions(productLine)
		if err != nil {
			return err
		}
		if err := validate.SnpAttestation(quote.sev, valOpts); err != nil {
			return err
		}
	case policy.PlatformTDX:
		if err := assembled.artifact.ValidateTDXQuote(assembled.machine.TDX, quote.tdx, quote.tdxTCBEvaluationDataNumber); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported platform %q", quote.Platform)
	}

	if assembled.Expected.CodeMeasurement != nil {
		if err := assembled.Expected.CodeMeasurement.Equals(quote.Measurement); err != nil {
			return err
		}
	}
	return nil
}

// VerifyCPUEvidenceV3 composes AuthenticateQuoteV3, AssemblePolicyV3, and
// ValidateQuoteV3 without a launch-measurement expectation; callers must
// compare the returned Measurement against verified code provenance.
func VerifyCPUEvidenceV3(doc *DocumentV3, expectedReportData [64]byte, endorsements *policy.Artifact) (*EvidenceV3, error) {
	quote, err := AuthenticateQuoteV3(doc)
	if err != nil {
		return nil, err
	}
	assembled, err := AssemblePolicyV3(endorsements, ExpectedValues{ReportData: expectedReportData}, quote)
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
