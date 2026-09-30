package quote

import (
	"encoding/base64"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/errs"
)

// CPUEvidence is the hardware report or quote to authenticate.
type CPUEvidence struct {
	// Format selects the platform, e.g. document.SEVSNPReportV1Format.
	Format string
	// Report is the raw report (SEV-SNP) or quote (TDX).
	Report []byte
}

// EvidenceFromDocument extracts the CPU evidence from doc. Its endorsement
// collateral comes from doc.CPUEndorsements.
func EvidenceFromDocument(doc *document.Document) (ev CPUEvidence, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if doc == nil {
		return ev, &errs.ConfigurationError{Err: fmt.Errorf("document is required")}
	}
	report, err := base64.StdEncoding.DecodeString(doc.CPUEvidence.ReportBase64)
	if err != nil {
		return ev, fmt.Errorf("decoding cpu_evidence report: %w", err)
	}
	return CPUEvidence{Format: doc.CPUEvidence.Format, Report: report}, nil
}
