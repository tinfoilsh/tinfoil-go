package attestation

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const RTMR3_ZERO = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

type PredicateType string

const (
	// CC guest v2 types include the TLS key fingerprint and optionally HPKE public key
	SevGuestV2 PredicateType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	TdxGuestV2 PredicateType = "https://tinfoil.sh/predicate/tdx-guest/v2"

	SnpTdxMultiPlatformV1 PredicateType = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"

	attestationEndpoint = "/.well-known/tinfoil-attestation"
)

var (
	ErrFormatMismatch              = errors.New("attestation format mismatch")
	ErrMeasurementMismatch         = errors.New("measurement mismatch")
	ErrRtmr1Mismatch               = errors.New("RTMR1 mismatch")
	ErrRtmr2Mismatch               = errors.New("RTMR2 mismatch")
	ErrRtmr3Mismatch               = errors.New("RTMR3 mismatch")
	ErrFewRegisters                = errors.New("fewer registers than expected")
	ErrMultiPlatformMismatch       = errors.New("multi-platform measurement mismatch")
	ErrMultiPlatformSevSnpMismatch = errors.New("multi-platform SEV-SNP measurement mismatch")
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

type Verification struct {
	Measurement    *Measurement `json:"measurement"`
	TLSPublicKeyFP string       `json:"tls_public_key,omitempty"`
	HPKEPublicKey  string       `json:"hpke_public_key,omitempty"`
}

func (m *Measurement) EqualsDisplay(other *Measurement) (string, error) {
	// Base case: if both measurements are multi-platform, compare directly
	if m.Type == SnpTdxMultiPlatformV1 && other.Type == SnpTdxMultiPlatformV1 {
		if !slices.Equal(m.Registers, other.Registers) {
			return "", ErrMultiPlatformMismatch
		}
		return "MP-MP exact match", nil
	}

	// Flip comparison order for multi-platform measurements
	if other.Type == SnpTdxMultiPlatformV1 {
		return other.EqualsDisplay(m)
	}

	if m.Type == SnpTdxMultiPlatformV1 {
		var err error
		var out strings.Builder

		if len(m.Registers) < 3 {
			return "", ErrFewRegisters
		}

		expectedSnp := m.Registers[0]
		expectedRtmr1 := m.Registers[1]
		expectedRtmr2 := m.Registers[2]
		// For now, we expect all RTMR3s to be zeros
		expectedRtmr3 := RTMR3_ZERO

		switch other.Type {
		case TdxGuestV2:
			if len(other.Registers) < 5 {
				return "MP-TDX unable to compare, too few TDX registers", ErrFewRegisters
			}

			actualRtmr1 := other.Registers[2] // 0 is MRTD, 1 is RTMR0
			actualRtmr2 := other.Registers[3]
			actualRtmr3 := other.Registers[4]

			out.WriteString(fmt.Sprintf("[i] SNP   %s\n", expectedSnp))

			if expectedRtmr1 != actualRtmr1 {
				out.WriteString(fmt.Sprintf("[-] RTMR1 %s != %s\n", expectedRtmr1, actualRtmr1))
				err = errors.Join(err, ErrRtmr1Mismatch)
			}
			if expectedRtmr2 != actualRtmr2 {
				out.WriteString(fmt.Sprintf("[-] RTMR2 %s != %s\n", expectedRtmr2, actualRtmr2))
				err = errors.Join(err, ErrRtmr2Mismatch)
			}
			if expectedRtmr3 != actualRtmr3 {
				out.WriteString(fmt.Sprintf("[-] RTMR3 %s != %s\n", expectedRtmr3, actualRtmr3))
				err = errors.Join(err, ErrRtmr3Mismatch)
			}

			if err == nil {
				out.WriteString(fmt.Sprintf("[+] RTMR1 %s\n[+] RTMR2 %s\n[+] RTMR3 %s\n", expectedRtmr1, expectedRtmr2, expectedRtmr3))
			}

			return strings.TrimRight(out.String(), "\n"), err
		case SevGuestV2:
			actualSnp := other.Registers[0]

			if expectedSnp != actualSnp {
				out.WriteString(fmt.Sprintf("[-] SNP   %s != %s\n", expectedSnp, actualSnp))
				err = ErrMultiPlatformSevSnpMismatch
			} else {
				out.WriteString(fmt.Sprintf("[+] SNP   %s\n", expectedSnp))
			}

			out.WriteString(fmt.Sprintf("[i] RTMR1 %s\n[i] RTMR2 %s", expectedRtmr1, expectedRtmr2))

			return strings.TrimRight(out.String(), "\n"), err
		default:
			return "", fmt.Errorf("unsupported enclave platform for multi-platform code measurements: %s", other.Type)
		}
	}

	if m.Type != other.Type {
		return "", ErrFormatMismatch
	}

	if !slices.Equal(m.Registers, other.Registers) {
		return "", ErrMeasurementMismatch
	}

	return "", nil
}

func (m *Measurement) Equals(other *Measurement) error {
	_, err := m.EqualsDisplay(other)
	return err
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

// KeyFP returns the fingerprint of a given ECDSA public key
func KeyFP(publicKey *ecdsa.PublicKey) string {
	bytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}

// CertPubkeyFP returns the fingerprint of the public key of a given certificate
func CertPubkeyFP(cert *x509.Certificate) (string, error) {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}

	return KeyFP(pubKey), nil
}

// ConnectionCertFP gets the KeyFP of the public key of a TLS connection state
func ConnectionCertFP(c tls.ConnectionState) (string, error) {
	if len(c.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificates")
	}
	cert := c.PeerCertificates[0]
	return CertPubkeyFP(cert)
}
