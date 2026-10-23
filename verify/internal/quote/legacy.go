package quote

import (
	"cmp"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// LegacyReferenceValues prepares the legacy repository-release contract.
type LegacyReferenceValues struct {
	Endorsements *policy.Artifact
	// SEVSNP and TDX are the registers the release fixes on each platform.
	SEVSNP measurement.ExpectedSEVSNP
	TDX    measurement.ExpectedTDX
	Shape  *policy.Shape
}

func (r LegacyReferenceValues) resolve(q *Authenticated, pins measurement.Expected) (*resolvedValues, error) {
	resolved, err := resolvePolicy(r.Endorsements, q)
	if err != nil {
		return nil, err
	}
	switch q.platform {
	case policy.PlatformSEVSNP:
		resolved.code = r.SEVSNP
	case policy.PlatformTDX:
		resolved.code = r.TDX
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.platform)
	}
	resolved.registers, err = applyPins(registersOf(resolved.code), q.platform, pins)
	if err != nil {
		return nil, err
	}
	switch q.platform {
	case policy.PlatformSEVSNP:
		resolved.hostData = resolved.policy.SEVSNP.HostData
	case policy.PlatformTDX:
		// The release fixes only RTMR1 and RTMR2; the platform endorsements
		// supply MRTD and RTMR0, and an unpinned RTMR3 must be zero.
		mrtd, rtmr0 := q.tdx.PlatformMeasurements()
		name, m, err := r.Endorsements.ResolvePlatformMeasurement(resolved.policy.TDX, r.Shape, mrtd, rtmr0)
		if err != nil {
			return nil, err
		}
		resolved.platformMeasurementName = name
		resolved.registers[0] = cmp.Or(resolved.registers[0], m.MRTD)
		resolved.registers[1] = cmp.Or(resolved.registers[1], m.RTMR0)
		resolved.registers[4] = cmp.Or(resolved.registers[4], measurement.Register{}.String())
	}
	return resolved, nil
}
