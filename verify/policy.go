package verify

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Policy holds the checks that a Verifier applies on top of its config trust.
// The zero Policy keeps every default: no register pins, the seven-day
// freshness bound, and runtime and platform artifacts endorsed by Tinfoil's
// public keys.
type Policy struct {
	// PinnedRegisters adds register checks. Each non-nil register must match
	// the enclave: it fills a register that the release leaves open, and must
	// equal one that the release fixes. Pins for one platform reject every
	// enclave on the other. It must be a measurement.ExpectedSEVSNP or
	// measurement.ExpectedTDX value, not a pointer, and is copied, so later
	// changes by the caller have no effect.
	PinnedRegisters measurement.Expected

	// FreshnessMaxAge bounds how old an authenticated witness may be. Zero
	// selects the seven-day default rather than disabling the check, and a
	// negative age is invalid.
	FreshnessMaxAge time.Duration

	// Artifacts selects how the runtime and platform artifacts are trusted.
	// Nil selects EndorsedArtifacts{}: endorsements that Tinfoil's public keys
	// approve.
	Artifacts ArtifactTrust
}

// apply copies policy into v after checking each field.
func (v *Verifier) apply(policy Policy) error {
	pins := policy.PinnedRegisters
	switch pins.(type) {
	case nil, measurement.ExpectedSEVSNP, measurement.ExpectedTDX:
	default:
		return fmt.Errorf("pinned registers must be a measurement.ExpectedSEVSNP or measurement.ExpectedTDX value, not %T", pins)
	}
	if pins != nil {
		v.pinnedRegisters = pins.Clone()
	}
	if policy.FreshnessMaxAge < 0 {
		return fmt.Errorf("freshness maximum age must not be negative")
	}
	if policy.FreshnessMaxAge > 0 {
		v.freshnessMaxAge = policy.FreshnessMaxAge
	}
	return v.applyArtifactTrust(policy.Artifacts)
}

func usageError(err error) error {
	if err == nil {
		return nil
	}
	return &UsageError{Err: err}
}
