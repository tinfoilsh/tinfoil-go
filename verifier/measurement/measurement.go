// Package measurement defines the measurement value types shared by code
// provenance and quote verification: register sets keyed by predicate type.
package measurement

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const RTMR3_ZERO = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

type PredicateType string

const (
	SevGuestV2 PredicateType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	TdxGuestV2 PredicateType = "https://tinfoil.sh/predicate/tdx-guest/v2"

	SnpTdxMultiPlatformV1 PredicateType = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
)

type Measurement struct {
	Type      PredicateType `json:"type"`
	Registers []string      `json:"registers"`
}

// ValidatePins checks caller-supplied register pins before verification.
func ValidatePins(pins *Measurement) error {
	if pins == nil {
		return nil
	}
	count := 1
	switch pins.Type {
	case SevGuestV2:
	case TdxGuestV2:
		count = 5
	default:
		return fmt.Errorf("pinned registers require an SNP or TDX measurement type")
	}
	if len(pins.Registers) != count {
		return fmt.Errorf("pinned registers require %d entries, got %d", count, len(pins.Registers))
	}
	for i, pin := range pins.Registers {
		if pin == "" {
			continue
		}
		decoded, err := hex.DecodeString(pin)
		if err != nil {
			return fmt.Errorf("pinned register %d is not hex: %w", i, err)
		}
		if len(decoded) != 48 {
			return fmt.Errorf("pinned register %d must be 48 bytes, got %d", i, len(decoded))
		}
	}
	return nil
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
