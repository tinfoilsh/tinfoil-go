package quote

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func AssembleIGVM(doc *document.Document, endorsements *policy.Artifact, runtime *igvm.Measurements, pins *measurement.Measurement, configHash [32]byte, q *Authenticated) (result *AssembledPolicy, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	reportData, err := q.reportData(doc)
	if err != nil {
		return nil, err
	}
	if endorsements == nil || runtime == nil || runtime.SNPLaunch == nil || runtime.TDXLaunch == nil {
		return nil, fmt.Errorf("platform and complete runtime endorsements are required")
	}
	want, err := RuntimeMeasurement(runtime, q.platform)
	if err != nil {
		return nil, err
	}
	if _, err := applyPins(want.Registers, want.Type, pins); err != nil {
		return nil, err
	}
	name, machine, err := endorsements.PolicyFor(q.identity, q.platform)
	if err != nil {
		return nil, err
	}
	result = &AssembledPolicy{PolicyName: name, quote: *q}
	switch q.platform {
	case policy.PlatformSEVSNP:
		result.sev, err = sev.AssembleIGVM(machine.SEVSNP, q.sev, runtime.SNPLaunch, configHash, reportData)
	case policy.PlatformTDX:
		result.tdx, err = tdx.AssembleIGVM(machine.TDX, runtime.TDXLaunch, configHash, reportData)
	default:
		return nil, fmt.Errorf("unsupported platform %q", q.platform)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func RuntimeMeasurement(runtime *igvm.Measurements, platform string) (*measurement.Measurement, error) {
	switch platform {
	case policy.PlatformSEVSNP:
		return &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{runtime.SNPLaunch.Measurement}}, nil
	case policy.PlatformTDX:
		registers := runtime.TDXLaunch.Registers()
		return &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: registers[:]}, nil
	default:
		return nil, fmt.Errorf("unsupported platform %q", platform)
	}
}
