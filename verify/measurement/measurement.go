// Package measurement defines the register values verification reports and
// accepts: what a CPU measured at launch, and the registers a release or a
// caller expects it to have measured. Each is a closed set with one type per
// hardware platform, so callers distinguish them with a type switch.
package measurement

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// RegisterSize is the size of every SEV-SNP and TDX measurement register.
const RegisterSize = 48

// Register is one measurement register. Its text form is lowercase hex.
type Register [RegisterSize]byte

// ParseRegister decodes a register from hex in either case.
func ParseRegister(s string) (Register, error) {
	var r Register
	if len(s) != 2*RegisterSize {
		return r, fmt.Errorf("register must be %d hex characters, got %d", 2*RegisterSize, len(s))
	}
	if _, err := hex.Decode(r[:], []byte(s)); err != nil {
		return Register{}, fmt.Errorf("register is not hex: %w", err)
	}
	return r, nil
}

func (r Register) String() string { return hex.EncodeToString(r[:]) }

// MarshalText encodes the register as lowercase hex.
func (r Register) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText decodes the register from hex in either case.
func (r *Register) UnmarshalText(text []byte) error {
	parsed, err := ParseRegister(string(text))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// Measurement is the set of registers a CPU measured at launch: SEVSNP or TDX.
// The concrete type is always a value, never a pointer. The set is closed:
// only this package implements it, and a new platform adds a type here.
type Measurement interface {
	fmt.Stringer
	isMeasurement()
}

// SEVSNP is an AMD SEV-SNP launch measurement.
type SEVSNP struct {
	Launch Register
}

// TDX is an Intel TDX build-time measurement and its four runtime registers.
type TDX struct {
	MRTD, RTMR0, RTMR1, RTMR2, RTMR3 Register
}

func (SEVSNP) isMeasurement() {}
func (TDX) isMeasurement()    {}

func (m SEVSNP) String() string {
	return format("SEV-SNP", []string{"Launch"}, []*Register{&m.Launch})
}

func (m TDX) String() string {
	return format("TDX", tdxLabels, []*Register{&m.MRTD, &m.RTMR0, &m.RTMR1, &m.RTMR2, &m.RTMR3})
}

// Expected is a set of registers a measurement must match, where a nil
// register is unconstrained: the registers a release fixes, or a caller's
// pins. It is ExpectedSEVSNP or ExpectedTDX, always a value, and the set is
// closed like Measurement's.
type Expected interface {
	fmt.Stringer
	// Clone returns a copy that shares no registers with the original.
	Clone() Expected
	isExpected()
}

// ExpectedSEVSNP constrains an SEV-SNP launch measurement.
type ExpectedSEVSNP struct {
	Launch *Register
}

// ExpectedTDX constrains a TDX measurement register by register.
type ExpectedTDX struct {
	MRTD, RTMR0, RTMR1, RTMR2, RTMR3 *Register
}

func (ExpectedSEVSNP) isExpected() {}
func (ExpectedTDX) isExpected()    {}

func (e ExpectedSEVSNP) Clone() Expected {
	return ExpectedSEVSNP{Launch: cloneRegister(e.Launch)}
}

func (e ExpectedTDX) Clone() Expected {
	return ExpectedTDX{
		MRTD: cloneRegister(e.MRTD), RTMR0: cloneRegister(e.RTMR0),
		RTMR1: cloneRegister(e.RTMR1), RTMR2: cloneRegister(e.RTMR2), RTMR3: cloneRegister(e.RTMR3),
	}
}

func cloneRegister(r *Register) *Register {
	if r == nil {
		return nil
	}
	copied := *r
	return &copied
}

func (e ExpectedSEVSNP) String() string {
	return format("SEV-SNP", []string{"Launch"}, []*Register{e.Launch})
}

func (e ExpectedTDX) String() string {
	return format("TDX", tdxLabels, []*Register{e.MRTD, e.RTMR0, e.RTMR1, e.RTMR2, e.RTMR3})
}

var tdxLabels = []string{"MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"}

// format writes the platform and one labeled register per line, with "any"
// for an unconstrained register.
func format(platform string, labels []string, registers []*Register) string {
	var out strings.Builder
	out.WriteString(platform)
	for i, register := range registers {
		value := "any"
		if register != nil {
			value = register.String()
		}
		fmt.Fprintf(&out, "\n%-6s %s", labels[i], value)
	}
	return out.String()
}
