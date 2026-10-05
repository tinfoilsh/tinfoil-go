package verify

import (
	"fmt"
	"slices"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
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

// WithFreshnessMaxAge bounds how old an authenticated witness may be, and how
// long a config approval stays acceptable. Zero leaves the bound unchanged, so
// an unset policy field keeps the seven-day default rather than disabling the
// check; a negative age is invalid. There is no upper bound.
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

// WithSoftwareIdentity sets the verifier recorded in each result's metadata, for
// an SDK built on this one. The default is this module's name and version.
func WithSoftwareIdentity(identity SoftwareIdentity) Option {
	return func(v *Verifier) error {
		if identity.Name == "" {
			return fmt.Errorf("software identity name is required")
		}
		v.identity = identity
		return nil
	}
}

// WithIgnoreFreshness skips code and platform freshness witnesses for archived
// documents. FreshnessExpiresAt is zero; certificate validity and all other
// attestation checks still apply.
func WithIgnoreFreshness() Option {
	return func(v *Verifier) error {
		v.ignoreFreshness = true
		return nil
	}
}

// WithConfigSigningKeys pins the registry keys that may approve a config, and
// the audit scope each is authorized for. Nothing in a document can add one,
// and VerifyConfig refuses to run without them.
func WithConfigSigningKeys(keys []endorsement.SigningKey) Option {
	return func(v *Verifier) error {
		if len(keys) == 0 {
			return fmt.Errorf("at least one config signing key is required")
		}
		v.configKeys = slices.Clone(keys)
		return nil
	}
}

func configurationError(err error) error {
	if err == nil {
		return nil
	}
	return &errs.ConfigurationError{Err: err}
}
