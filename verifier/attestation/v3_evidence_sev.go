package attestation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

func authenticateSevQuoteV3(doc *DocumentV3) (*AuthenticatedQuote, error) {
	// The VCEK comes from the document's own collateral; its chain is
	// verified against the pinned AMD root, so the entry is untrusted input.
	entry, ok := doc.endorsementCollateral(CollateralAMDVCEKV1Format, SubjectCPU)
	if !ok {
		return nil, fmt.Errorf("document carries no amd-vcek endorsement collateral for the cpu")
	}
	var data AMDVCEKCollateral
	if err := strictUnmarshal(entry.Data, &data); err != nil {
		return nil, fmt.Errorf("parsing amd-vcek collateral entry %q: %w", entry.ID, err)
	}
	vcekDER, err := base64.StdEncoding.DecodeString(data.VCEKDERBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding vcek_der_base64: %w", err)
	}

	att, err := verifySevSignature(doc.CPUEvidence.ReportBase64, false, vcekDER)
	if err != nil {
		return nil, err
	}
	report := att.GetReport()

	identity, err := policy.SEVIdentity(report.GetChipId())
	if err != nil {
		return nil, err
	}

	return &AuthenticatedQuote{
		Platform:         policy.PlatformSEVSNP,
		PlatformIdentity: identity,
		Measurement: &Measurement{
			Type:      SevGuestV2,
			Registers: []string{hex.EncodeToString(report.Measurement)},
		},
		reportData: report.ReportData,
		sev:        att,
	}, nil
}
