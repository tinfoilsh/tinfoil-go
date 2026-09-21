package measurement

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const codeRegisterBytes = 48

// CodeMeasurement contains the workload registers published with a release.
// Supply either platform's measurement, or both for a multiplatform release.
type CodeMeasurement struct {
	SNPMeasurement string          `json:"snp_measurement,omitempty"`
	TDXMeasurement *TDXMeasurement `json:"tdx_measurement,omitempty"`
}

// TDXMeasurement pins workload registers, not MRTD, RTMR0, or RTMR3.
type TDXMeasurement struct {
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
}

// ValidateCode returns an independent, lowercase-normalized workload pin.
func ValidateCode(m *CodeMeasurement) (*CodeMeasurement, error) {
	if m == nil || m.SNPMeasurement == "" && m.TDXMeasurement == nil {
		return nil, fmt.Errorf("snp_measurement or tdx_measurement is required")
	}
	result := &CodeMeasurement{}
	var err error
	if m.SNPMeasurement != "" {
		result.SNPMeasurement, err = normalizeCodeRegister(m.SNPMeasurement)
		if err != nil {
			return nil, fmt.Errorf("snp_measurement: %w", err)
		}
	}
	if m.TDXMeasurement != nil {
		rtmr1, err := normalizeCodeRegister(m.TDXMeasurement.RTMR1)
		if err != nil {
			return nil, fmt.Errorf("rtmr1: %w", err)
		}
		rtmr2, err := normalizeCodeRegister(m.TDXMeasurement.RTMR2)
		if err != nil {
			return nil, fmt.Errorf("rtmr2: %w", err)
		}
		result.TDXMeasurement = &TDXMeasurement{RTMR1: rtmr1, RTMR2: rtmr2}
	}
	return result, nil
}

func normalizeCodeRegister(register string) (string, error) {
	if len(register) != hex.EncodedLen(codeRegisterBytes) {
		return "", fmt.Errorf("expected %d hex characters, got %d", hex.EncodedLen(codeRegisterBytes), len(register))
	}
	if _, err := hex.DecodeString(register); err != nil {
		return "", fmt.Errorf("invalid hexadecimal register: %w", err)
	}
	return strings.ToLower(register), nil
}
