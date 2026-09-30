package document

import (
	"encoding/json/v2"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/errs"
)

// CPUEndorsements is the decoded vendor collateral that chains the document's
// CPU evidence to its vendor root. A nil field means the document carries no
// such collateral; which fields are required depends on the evidence format,
// and CPU-evidence authentication rejects evidence missing one.
type CPUEndorsements struct {
	AMDVCEK  *AMDVCEK
	AMDCRL   *AMDCRL
	IntelPCS *IntelPCS
}

// IntelPCS is decoded intel-pcs collateral: Intel PCS responses captured so a
// verifier replays them instead of fetching.
type IntelPCS struct {
	Responses []PCSResponse
}

// PCSResponse is one decoded captured Intel PCS response. Headers are kept
// because Intel delivers issuer chains in response headers.
type PCSResponse struct {
	URL     string
	Headers map[string][]string
	Body    []byte
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

// CPUEndorsements decodes the endorsement collateral the document's CPU
// evidence format uses, for the reserved "cpu" subject. Collateral the
// document does not carry is left nil; collateral that is present but
// malformed is an error. Entries for other platforms are ignored.
func (d *Document) CPUEndorsements() (result CPUEndorsements, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	var en CPUEndorsements
	switch d.evidence.Format {
	case SEVSNPReportV1Format:
		if entry, ok := d.endorsementCollateral(CollateralAMDVCEKV1Format, SubjectCPU); ok {
			var data amdVCEKCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return en, fmt.Errorf("parsing amd-vcek collateral entry %q: %w", entry.ID, err)
			}
			der, err := data.vcekDER()
			if err != nil {
				return en, fmt.Errorf("amd-vcek collateral entry %q: %w", entry.ID, err)
			}
			en.AMDVCEK = &AMDVCEK{VCEKDER: der, CertChainPEM: data.CertChainPEM}
		}
		if entry, ok := d.endorsementCollateral(CollateralAMDCRLV1Format, SubjectCPU); ok {
			var data amdCRLCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return en, fmt.Errorf("parsing amd-crl collateral entry %q: %w", entry.ID, err)
			}
			der, err := data.crlDER()
			if err != nil {
				return en, fmt.Errorf("amd-crl collateral entry %q: %w", entry.ID, err)
			}
			en.AMDCRL = &AMDCRL{CRLDER: der}
		}
	case TDXQuoteV1Format:
		if entry, ok := d.endorsementCollateral(CollateralIntelPCSV1Format, SubjectCPU); ok {
			var data intelPCSCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return en, fmt.Errorf("parsing intel-pcs collateral entry %q: %w", entry.ID, err)
			}
			pcs := &IntelPCS{Responses: make([]PCSResponse, 0, len(data.Responses))}
			for i := range data.Responses {
				body, err := data.Responses[i].body()
				if err != nil {
					return en, fmt.Errorf("intel-pcs collateral entry %q response %d: %w", entry.ID, i, err)
				}
				pcs.Responses = append(pcs.Responses, PCSResponse{URL: data.Responses[i].URL, Headers: data.Responses[i].Headers, Body: body})
			}
			en.IntelPCS = pcs
		}
	}
	return en, nil
}
