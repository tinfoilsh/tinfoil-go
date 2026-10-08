package quote

import (
	"cmp"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// LegacyReferenceValues prepares the legacy repository-release contract.
type LegacyReferenceValues struct {
	Endorsements *policy.Artifact
	Code         *measurement.Measurement
	Shape        *policy.Shape
}

func (r LegacyReferenceValues) resolve(q *Authenticated, pins *measurement.Measurement) (*resolvedValues, error) {
	if r.Code == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("assembling policy: expected code measurement is required")}
	}
	if q.platform == policy.PlatformTDX && r.Shape == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("assembling policy: the code artifact's VM shape is required")}
	}
	code := r.Code
	resolved, err := resolvePolicy(r.Endorsements, q)
	if err != nil {
		return nil, err
	}
	resolved.code = code
	resolved.registers, err = layout(code, pins, q)
	if err != nil {
		return nil, err
	}
	switch q.platform {
	case policy.PlatformSEVSNP:
		resolved.hostData = resolved.policy.SEVSNP.HostData
	case policy.PlatformTDX:
		mrtd, rtmr0, err := q.tdx.PlatformMeasurements()
		if err != nil {
			return nil, err
		}
		name, m, err := r.Endorsements.ResolvePlatformMeasurement(resolved.policy.TDX, r.Shape, mrtd, rtmr0)
		if err != nil {
			return nil, err
		}
		resolved.platformMeasurementName = name
		resolved.registers[0] = cmp.Or(resolved.registers[0], m.MRTD)
		resolved.registers[1] = cmp.Or(resolved.registers[1], m.RTMR0)
		resolved.registers[4] = cmp.Or(resolved.registers[4], measurement.RTMR3_ZERO)
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.platform)
	}
	return resolved, nil
}

// layout maps code and pins to enclave registers, leaving platform defaults empty.
func layout(code, pins *measurement.Measurement, q *Authenticated) ([]string, error) {
	if code.Type != measurement.SnpTdxMultiPlatformV1 || len(code.Registers) != 3 {
		return nil, fmt.Errorf("code measurement is %s with %d registers, want %s with 3", code.Type, len(code.Registers), measurement.SnpTdxMultiPlatformV1)
	}
	registers := []string{code.Registers[0]}
	enclaveType := measurement.SevGuestV2
	if q.platform == policy.PlatformTDX {
		registers = []string{"", "", code.Registers[1], code.Registers[2], ""}
		enclaveType = measurement.TdxGuestV2
	}
	return applyPins(registers, enclaveType, pins)
}
