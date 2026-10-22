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

func (r ConfigReferenceValues) resolve(q *Authenticated, pins *measurement.Measurement) (*resolvedValues, error) {
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
		resolved.code = &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{r.Runtime.SNPLaunch.Measurement}}
	case policy.PlatformTDX:
		if len(resolved.policy.TDX.PlatformMeasurements) != 0 {
			return nil, fmt.Errorf("config runtime cannot be combined with platform_measurements")
		}
		copy(resolved.configID[:], r.Hash[:])
		registers := r.Runtime.TDXLaunch.Registers()
		resolved.code = &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: registers[:]}
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.platform)
	}
	resolved.registers, err = applyPins(resolved.code.Registers, resolved.code.Type, pins)
	return resolved, err
}
