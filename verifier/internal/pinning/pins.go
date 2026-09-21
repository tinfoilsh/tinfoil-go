// Package pinning validates caller-supplied register pins before verification.
package pinning

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

func Validate(pins *measurement.Measurement) error {
	if pins == nil {
		return nil
	}
	count := 1
	switch pins.Type {
	case measurement.SevGuestV2:
	case measurement.TdxGuestV2:
		count = 5
	default:
		return fmt.Errorf("pinned registers require an SNP or TDX measurement type")
	}
	if len(pins.Registers) != count {
		return fmt.Errorf("pinned registers require %d entries, got %d", count, len(pins.Registers))
	}
	for i, pin := range pins.Registers {
		if pin != "" {
			if _, err := policy.DecodeHex(fmt.Sprintf("pinned register %d", i), pin, 48); err != nil {
				return err
			}
		}
	}
	return nil
}
