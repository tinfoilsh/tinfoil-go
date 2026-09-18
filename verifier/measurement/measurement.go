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

// Fingerprint returns the register value of a single-register measurement, or
// SHA-256 over the type URL and all register values for multi-register ones.
func (m *Measurement) Fingerprint() string {
	if len(m.Registers) == 1 {
		return m.Registers[0]
	}
	hash := sha256.Sum256([]byte(string(m.Type) + strings.Join(m.Registers, "")))
	return fmt.Sprintf("%x", hash)
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
