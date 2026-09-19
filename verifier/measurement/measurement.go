// Package measurement defines the measurement value types shared by code
// provenance and quote verification: register sets keyed by predicate type,
// their equality semantics, and canonical target-platform fingerprints.
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

// Fingerprint computes a canonical target-platform fingerprint. A multiplatform
// source is expanded to the target's register layout using authenticated
// hardware measurements for TDX. Equivalent code and enclave measurements
// produce the same fingerprint regardless of the source predicate type.
// SEV returns its lowercase register; TDX hashes the target type URL followed
// by all five lowercase, fixed-width hex registers (no separator).
func Fingerprint(m *Measurement, hw *HardwareMeasurement, targetType PredicateType) (string, error) {
	validated, err := ValidatePin(m)
	if err != nil {
		return "", fmt.Errorf("invalid measurement: %w", err)
	}
	m = validated
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
		if targetType != TdxGuestV2 {
			return "", fmt.Errorf("TDX measurement cannot target %s", targetType)
		}
		registers = m.Registers
	case SevGuestV2:
		if targetType != SevGuestV2 {
			return "", fmt.Errorf("SEV measurement cannot target %s", targetType)
		}
		registers = m.Registers
	default:
		return "", fmt.Errorf("unsupported measurement type %s", m.Type)
	}

	// This also validates and normalizes the hardware registers used to expand
	// a multiplatform source, without changing either caller-owned input.
	runtime, err := ValidatePin(&Measurement{Type: targetType, Registers: registers})
	if err != nil {
		return "", fmt.Errorf("invalid target measurement: %w", err)
	}
	registers = runtime.Registers
	if len(registers) == 1 {
		return registers[0], nil
	}

	all := string(targetType) + strings.Join(registers, "")
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
