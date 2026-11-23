package quote

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// ConfigReferenceValues prepares the runtime v1 and config-endorsement v1 contract.
type ConfigReferenceValues struct {
	Endorsements *policy.Artifact
	Runtime      *runtime.Measurements
	Hash         [sha256.Size]byte
}

func (r ConfigReferenceValues) resolve(q *Authenticated, pins measurement.Expected) (*resolvedValues, error) {
	if r.Runtime == nil || r.Runtime.SNPLaunch == nil || r.Runtime.TDXLaunch == nil {
		return nil, fmt.Errorf("complete runtime endorsements are required")
	}
	resolved, err := resolvePolicy(r.Endorsements, q)
	if err != nil {
		return nil, err
	}
	switch q.platform {
	case policy.PlatformSEVSNP:
		if resolved.policy.SEVSNP.HostData != "" {
			return nil, fmt.Errorf("config runtime cannot be combined with platform host_data")
		}
		resolved.hostData = hex.EncodeToString(r.Hash[:])
	case policy.PlatformTDX:
		if len(resolved.policy.TDX.PlatformMeasurements) != 0 {
			return nil, fmt.Errorf("config runtime cannot be combined with platform_measurements")
		}
		copy(resolved.configID[:], r.Hash[:])
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.platform)
	}
	if resolved.code, err = r.code(q.platform); err != nil {
		return nil, err
	}
	resolved.expected, err = applyPins(resolved.code, q.platform, pins)
	return resolved, err
}

func (r ConfigReferenceValues) code(platform string) (measurement.Expected, error) {
	if r.Runtime == nil || r.Runtime.SNPLaunch == nil || r.Runtime.TDXLaunch == nil {
		return nil, fmt.Errorf("complete runtime endorsements are required")
	}
	switch platform {
	case policy.PlatformSEVSNP:
		launch, err := measurement.ParseRegister(r.Runtime.SNPLaunch.Measurement)
		if err != nil {
			return nil, fmt.Errorf("runtime SNP launch measurement: %w", err)
		}
		return measurement.ExpectedSEVSNP{Launch: &launch}, nil
	case policy.PlatformTDX:
		var registers [5]*measurement.Register
		for i, value := range r.Runtime.TDXLaunch.Registers() {
			register, err := measurement.ParseRegister(value)
			if err != nil {
				return nil, fmt.Errorf("runtime TDX register %d: %w", i, err)
			}
			registers[i] = &register
		}
		return measurement.ExpectedTDX{MRTD: registers[0], RTMR0: registers[1], RTMR1: registers[2], RTMR2: registers[3], RTMR3: registers[4]}, nil
	default:
		return nil, fmt.Errorf("unsupported platform %q", platform)
	}
}
