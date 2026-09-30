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
	AMDVCEK *AMDVCEK
	AMDCRL  *AMDCRL
	// IntelPCS stays undecoded: the replay getter decodes each captured body
	// only when the verification library requests it.
	IntelPCS *IntelPCSCollateral
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
	switch d.CPUEvidence.Format {
	case SEVSNPReportV1Format:
		if entry, ok := d.EndorsementCollateral(CollateralAMDVCEKV1Format, SubjectCPU); ok {
			var data AMDVCEKCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return en, fmt.Errorf("parsing amd-vcek collateral entry %q: %w", entry.ID, err)
			}
			der, err := data.VCEKDER()
			if err != nil {
				return en, fmt.Errorf("amd-vcek collateral entry %q: %w", entry.ID, err)
			}
			en.AMDVCEK = &AMDVCEK{VCEKDER: der, CertChainPEM: data.CertChainPEM}
		}
		if entry, ok := d.EndorsementCollateral(CollateralAMDCRLV1Format, SubjectCPU); ok {
			var data AMDCRLCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return en, fmt.Errorf("parsing amd-crl collateral entry %q: %w", entry.ID, err)
			}
			der, err := data.CRLDER()
			if err != nil {
				return en, fmt.Errorf("amd-crl collateral entry %q: %w", entry.ID, err)
			}
			en.AMDCRL = &AMDCRL{CRLDER: der}
		}
	case TDXQuoteV1Format:
		if entry, ok := d.EndorsementCollateral(CollateralIntelPCSV1Format, SubjectCPU); ok {
			var data IntelPCSCollateral
			if err := json.Unmarshal(entry.Data, &data, json.RejectUnknownMembers(true)); err != nil {
				return en, fmt.Errorf("parsing intel-pcs collateral entry %q: %w", entry.ID, err)
			}
			en.IntelPCS = &data
		}
	}
	return en, nil
}
