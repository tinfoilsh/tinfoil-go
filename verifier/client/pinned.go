package client

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

// PinnedNoDigest identifies caller-supplied code, not an authenticated release digest.
const PinnedNoDigest = "pinned_no_digest"

// PinnedNoRepo identifies results without a verified source repository.
const PinnedNoRepo = "pinned_no_repo"

// Unspecified platform entries stay empty; they must never become a fallback
// expectation for evidence from a platform the caller did not pin.
func pinnedCodeMeasurement(pin *measurement.CodeMeasurement, format string) (*measurement.Measurement, error) {
	switch format {
	case envelope.SEVSNPReportV1Format:
		if pin.SNPMeasurement == "" {
			return nil, fmt.Errorf("SEV-SNP enclave requires snp_measurement")
		}
	case envelope.TDXQuoteV1Format:
		if pin.TDXMeasurement == nil {
			return nil, fmt.Errorf("TDX enclave requires tdx_measurement")
		}
	default:
		return nil, fmt.Errorf("unsupported cpu_evidence format %q", format)
	}
	registers := []string{pin.SNPMeasurement, "", ""}
	if pin.TDXMeasurement != nil {
		registers[1], registers[2] = pin.TDXMeasurement.RTMR1, pin.TDXMeasurement.RTMR2
	}
	return &measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: registers}, nil
}
