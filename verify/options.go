package verify

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Option configures a Verifier. Options are applied in order by NewVerifier,
// which reports the first one that fails as a ConfigurationError.
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

// WithVerificationTime appraises archived evidence at a fixed, nonzero instant.
// Freshness and hardware certificate/collateral validity are checked at that time.
// The caller must independently authenticate this time; the SDK does not prove
// when a receipt existed or account for revocations learned after that instant.
// Omit this option to use the current time. It is not a live-client option.
func WithVerificationTime(at time.Time) Option {
	return func(v *Verifier) error {
		if at.IsZero() {
			return fmt.Errorf("verification time must not be zero")
		}
		instant := at.UTC()
		v.now = func() time.Time { return instant }
		return nil
	}
}

func configurationError(err error) error {
	if err == nil {
		return nil
	}
	return &errs.ConfigurationError{Err: err}
}
