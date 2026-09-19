package measurement

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// registerHexLength is the encoded length of a 48-byte register.
const registerHexLength = 96

var (
	ErrPinnedMeasurementNil   = errors.New("pinned measurement is nil")
	ErrPinnedMeasurementType  = errors.New("unsupported pinned measurement type")
	ErrPinnedRegisterCount    = errors.New("pinned measurement has the wrong number of registers")
	ErrPinnedRegisterEncoding = errors.New("pinned measurement register is not 48-byte hex")
)

// registerCount returns the register layout a code measurement of the given
// type must carry.
func registerCount(t PredicateType) (int, bool) {
	switch t {
	case SevGuestV2:
		return 1, true
	case TdxGuestV2:
		return 5, true
	case SnpTdxMultiPlatformV1:
		return 3, true
	}
	return 0, false
}

// ValidatePin checks that a caller-supplied code measurement has a supported
// type, the register layout that type requires, and well-formed register
// values. It returns an independent, lowercase-normalized copy so the caller's
// value cannot change what verification later accepts.
func ValidatePin(m *Measurement) (*Measurement, error) {
	if m == nil {
		return nil, ErrPinnedMeasurementNil
	}
	want, ok := registerCount(m.Type)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrPinnedMeasurementType, m.Type)
	}
	if len(m.Registers) != want {
		return nil, fmt.Errorf("%w: %s has %d registers, want %d", ErrPinnedRegisterCount, m.Type, len(m.Registers), want)
	}

	registers := make([]string, len(m.Registers))
	for i, register := range m.Registers {
		normalized := strings.ToLower(register)
		if len(normalized) != registerHexLength {
			return nil, fmt.Errorf("%w: register %d has %d characters, want %d", ErrPinnedRegisterEncoding, i, len(normalized), registerHexLength)
		}
		if _, err := hex.DecodeString(normalized); err != nil {
			return nil, fmt.Errorf("%w: register %d: %v", ErrPinnedRegisterEncoding, i, err)
		}
		registers[i] = normalized
	}
	return &Measurement{Type: m.Type, Registers: registers}, nil
}
