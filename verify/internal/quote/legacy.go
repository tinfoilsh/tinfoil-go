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
	resolved.expected, err = applyPins(resolved.code, q.platform, pins)
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
		platformMRTD, err := measurement.ParseRegister(m.MRTD)
		if err != nil {
			return nil, fmt.Errorf("platform measurement %q MRTD: %w", name, err)
		}
		platformRTMR0, err := measurement.ParseRegister(m.RTMR0)
		if err != nil {
			return nil, fmt.Errorf("platform measurement %q RTMR0: %w", name, err)
		}
		e, ok := resolved.expected.(measurement.ExpectedTDX)
		if !ok {
			return nil, fmt.Errorf("expected a TDX measurement, got %T", resolved.expected)
		}
		e.MRTD = cmp.Or(e.MRTD, &platformMRTD)
		e.RTMR0 = cmp.Or(e.RTMR0, &platformRTMR0)
		e.RTMR3 = cmp.Or(e.RTMR3, &measurement.Register{})
		resolved.expected = e
	}
	return resolved, nil
}
