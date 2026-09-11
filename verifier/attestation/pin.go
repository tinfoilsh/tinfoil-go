package attestation

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Register values are 48-byte digests, so a well-formed register is 96 hex
// characters.
const registerHexLength = 96

var (
	ErrPinnedMeasurementNil     = errors.New("pinned measurement is nil")
	ErrPinnedMeasurementType    = errors.New("unsupported pinned measurement type")
	ErrPinnedRegisterCount      = errors.New("pinned measurement has the wrong number of registers")
	ErrPinnedRegisterEncoding   = errors.New("pinned measurement register is not 48-byte hex")
	ErrHardwareMeasurementNil   = errors.New("hardware measurement entry is nil")
	ErrHardwareMeasurementID    = errors.New("hardware measurement entry is missing an ID")
	ErrHardwareRegisterEncoding = errors.New("hardware measurement register is not 48-byte hex")
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

func normalizeRegister(register string) (string, error) {
	normalized := strings.ToLower(register)
	if len(normalized) != registerHexLength {
		return "", fmt.Errorf("got %d characters, want %d", len(normalized), registerHexLength)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// ValidatePinnedMeasurement checks that a caller-supplied code measurement has
// a supported type, the register layout that type requires, and well-formed
// register values. It returns an independent, lowercase-normalized copy so the
// caller's value cannot change what verification later accepts.
func ValidatePinnedMeasurement(m *Measurement) (*Measurement, error) {
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
		normalized, err := normalizeRegister(register)
		if err != nil {
			return nil, fmt.Errorf("%w: register %d: %v", ErrPinnedRegisterEncoding, i, err)
		}
		registers[i] = normalized
	}
	return &Measurement{Type: m.Type, Registers: registers}, nil
}

// ValidateHardwareMeasurements checks caller-supplied TDX platform
// measurements and returns independent, lowercase-normalized copies. A nil
// slice or empty slice is returned as nil so callers can fall back to the
// published platform measurements.
func ValidateHardwareMeasurements(measurements []*HardwareMeasurement) ([]*HardwareMeasurement, error) {
	if len(measurements) == 0 {
		return nil, nil
	}
	validated := make([]*HardwareMeasurement, len(measurements))
	for i, measurement := range measurements {
		if measurement == nil {
			return nil, fmt.Errorf("%w: entry %d", ErrHardwareMeasurementNil, i)
		}
		if measurement.ID == "" {
			return nil, fmt.Errorf("%w: entry %d", ErrHardwareMeasurementID, i)
		}
		mrtd, err := normalizeRegister(measurement.MRTD)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d MRTD: %v", ErrHardwareRegisterEncoding, i, err)
		}
		rtmr0, err := normalizeRegister(measurement.RTMR0)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d RTMR0: %v", ErrHardwareRegisterEncoding, i, err)
		}
		validated[i] = &HardwareMeasurement{ID: measurement.ID, MRTD: mrtd, RTMR0: rtmr0}
	}
	return validated, nil
}
