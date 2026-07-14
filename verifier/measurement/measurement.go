// Package measurement defines the measurement value types shared by code
// provenance and quote verification: register sets keyed by predicate type,
// their equality semantics, and display fingerprints.
package measurement

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const RTMR3_ZERO = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

type PredicateType string

const (
	// CC guest v2 types include the TLS key fingerprint and optionally HPKE public key
	SevGuestV2 PredicateType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	TdxGuestV2 PredicateType = "https://tinfoil.sh/predicate/tdx-guest/v2"

	SnpTdxMultiPlatformV1 PredicateType = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
)

type Measurement struct {
	Type      PredicateType `json:"type"`
	Registers []string      `json:"registers"`
}

// Fingerprint computes a fingerprint for a measurement. For single-register
// measurements, the register value is returned directly. For multi-register
// measurements, SHA-256 is computed over the type URL concatenated with all
// register values (no separator).
func Fingerprint(m *Measurement, hw *HardwareMeasurement, targetType PredicateType) (string, error) {
	var registers []string

	switch m.Type {
	case SnpTdxMultiPlatformV1: // Source
		switch targetType {
		case SevGuestV2:
			registers = []string{m.Registers[0]}
		case TdxGuestV2:
			if hw == nil {
				return "", fmt.Errorf("hardware measurement required for TDX guest types")
			}
			registers = []string{hw.MRTD, hw.RTMR0, m.Registers[1], m.Registers[2], RTMR3_ZERO}
		default:
			return "", fmt.Errorf("unsupported target type %s", targetType)
		}
	case TdxGuestV2: // Runtime
		registers = []string{m.Registers[0], m.Registers[1], m.Registers[2], m.Registers[3], m.Registers[4]}
	case SevGuestV2:
		registers = []string{m.Registers[0]}
	default:
		return "", fmt.Errorf("unsupported measurement type %s", m.Type)
	}

	if len(registers) == 1 {
		return registers[0], nil
	}

	all := string(m.Type) + strings.Join(registers, "")
	hash := sha256.Sum256([]byte(all))
	return fmt.Sprintf("%x", hash), nil
}

func (m *Measurement) String() string {
	var out strings.Builder

	var platform []string
	switch m.Type {
	case SnpTdxMultiPlatformV1:
		platform = []string{"SNP", "RTMR1", "RTMR2"}
	case SevGuestV2:
		platform = []string{"SNP"}
	case TdxGuestV2:
		platform = []string{"MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"}
	}

	out.WriteString(string(m.Type))
	for i, register := range m.Registers {
		var label string
		if platform != nil && i < len(platform) {
			label = fmt.Sprintf("%-5s", platform[i])
		} else {
			label = fmt.Sprintf("[%d]", i)
		}
		out.WriteString(fmt.Sprintf("\n%s %s", label, register))
	}
	return out.String()
}
