package verifier

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/errs"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

// Option configures a Verifier. Options are applied in order by New, which
// reports the first one that fails as a ConfigurationError.
type Option func(*Verifier) error

// WithPinnedRegisters adds register checks; empty entries retain defaults.
// The measurement is copied, so later mutation by the caller has no effect.
// TDX order is [MRTD, RTMR0, RTMR1, RTMR2, RTMR3].
func WithPinnedRegisters(pins *measurement.Measurement) Option {
	return func(v *Verifier) error {
		pins = cloneMeasurement(pins)
		if err := measurement.ValidatePins(pins); err != nil {
			return err
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

func configurationError(err error) error {
	if err == nil {
		return nil
	}
	return &errs.ConfigurationError{Err: err}
}
