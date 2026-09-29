package quote

import (
	"encoding/base64"
	"encoding/json/v2"
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

// CPUEndorsements is the vendor collateral that chains CPU evidence to its
// root. A nil field means no such collateral was supplied; which fields are
// required depends on the evidence format.
type CPUEndorsements struct {
	AMDVCEK *AMDVCEK
	AMDCRL  *AMDCRL
	// IntelPCS stays undecoded: the replay getter decodes each captured body
	// only when the verification library requests it.
	IntelPCS *document.IntelPCSCollateral
}

// AMDVCEK is decoded amd-vcek collateral.
type AMDVCEK struct {
	VCEKDER []byte
	// CertChainPEM holds the ASK then ARK certificates.
	CertChainPEM string
}

// AMDCRL is decoded amd-crl collateral.
type AMDCRL struct {
	CRLDER []byte
}

// EvidenceFromDocument extracts the CPU evidence and the endorsement
// collateral its platform uses from doc. Collateral the document does not
// carry is left nil for Authenticate to reject; collateral that is present but
// malformed is an error here. Entries for other platforms are ignored.
func EvidenceFromDocument(doc *document.Document) (ev CPUEvidence, en CPUEndorsements, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	if doc == nil {
		return ev, en, &errs.ConfigurationError{Err: fmt.Errorf("document is required")}
	}
	report, err := base64.StdEncoding.DecodeString(doc.CPUEvidence.ReportBase64)
	if err != nil {
		return ev, en, fmt.Errorf("decoding cpu_evidence report: %w", err)
	}
	ev = CPUEvidence{Format: doc.CPUEvidence.Format, Report: report}

	switch ev.Format {
	case document.SEVSNPReportV1Format:
		if entry, ok := doc.EndorsementCollateral(document.CollateralAMDVCEKV1Format, document.SubjectCPU); ok {
			var data document.AMDVCEKCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return ev, en, fmt.Errorf("parsing amd-vcek collateral entry %q: %w", entry.ID, err)
			}
			der, err := data.VCEKDER()
			if err != nil {
				return ev, en, fmt.Errorf("amd-vcek collateral entry %q: %w", entry.ID, err)
			}
			en.AMDVCEK = &AMDVCEK{VCEKDER: der, CertChainPEM: data.CertChainPEM}
		}
		if entry, ok := doc.EndorsementCollateral(document.CollateralAMDCRLV1Format, document.SubjectCPU); ok {
			var data document.AMDCRLCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return ev, en, fmt.Errorf("parsing amd-crl collateral entry %q: %w", entry.ID, err)
			}
			der, err := data.CRLDER()
			if err != nil {
				return ev, en, fmt.Errorf("amd-crl collateral entry %q: %w", entry.ID, err)
			}
			en.AMDCRL = &AMDCRL{CRLDER: der}
		}
	case document.TDXQuoteV1Format:
		if entry, ok := doc.EndorsementCollateral(document.CollateralIntelPCSV1Format, document.SubjectCPU); ok {
			var data document.IntelPCSCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return ev, en, fmt.Errorf("parsing intel-pcs collateral entry %q: %w", entry.ID, err)
			}
			en.IntelPCS = &data
		}
	}
	return ev, en, nil
}
