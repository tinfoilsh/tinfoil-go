package measurement

import (
	"encoding/hex"
	"fmt"
)

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
