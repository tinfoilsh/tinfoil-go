package verify

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Option configures a Verifier. Options are applied in order by NewVerifier,
// which reports the first one that fails as a UsageError.
type Option func(*Verifier) error

// WithPinnedRegisters adds register checks. Each non-nil register in pins must
// match the enclave: it fills a register the release leaves open, and must
// equal one the release fixes. Pins for one platform reject every enclave on
// the other. pins must be a value, not a pointer, and is copied, so later
// changes by the caller have no effect.
func WithPinnedRegisters(pins measurement.Expected) Option {
	return func(v *Verifier) error {
		switch pins.(type) {
		case nil, measurement.ExpectedSEVSNP, measurement.ExpectedTDX:
		default:
			return fmt.Errorf("pinned registers must be a measurement.ExpectedSEVSNP or measurement.ExpectedTDX value, not %T", pins)
		}
		if pins != nil {
			pins = pins.Clone()
		}
		v.pinnedRegisters = pins
		return nil
	}
}

// WithFreshnessMaxAge bounds how old an authenticated witness may be. Zero
// leaves the bound unchanged, so an unset policy field keeps the seven-day
// default rather than disabling the check; a negative age is invalid.
func WithFreshnessMaxAge(maxAge time.Duration) Option {
	return func(v *Verifier) error {
		if maxAge < 0 {
			return fmt.Errorf("freshness maximum age must not be negative")
		}
		if maxAge > 0 {
			v.freshnessMaxAge = maxAge
		}
		return nil
	}
}

func usageError(err error) error {
	if err == nil {
		return nil
	}
	return &UsageError{Err: err}
}
