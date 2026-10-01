package quote

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/quote/tdx"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

func AssembleIGVM(doc *document.Document, endorsements *policy.Artifact, runtime *igvm.Measurements, pins *measurement.Measurement, configHash [32]byte, q *Authenticated) (result *AssembledPolicy, err error) {
	defer func() { err = errs.WrapAttestation(err) }()
	reportData, ok := doc.ExpectedReportData()
	if !ok || q == nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("a parsed document and authenticated quote are required")}
	}
	evidence := doc.CPUEvidence()
	if evidence.Format != q.evidence.Format || !bytes.Equal(evidence.Report, q.evidence.Report) {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("authenticated quote is not this document's CPU evidence")}
	}
	if endorsements == nil || runtime == nil || runtime.SNPLaunch == nil || runtime.TDXLaunch == nil {
		return nil, fmt.Errorf("platform and complete runtime endorsements are required")
	}
	want, err := RuntimeMeasurement(runtime, q.platform)
	if err != nil {
		return nil, err
	}
	if err := checkRuntimePins(want, pins); err != nil {
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

func checkRuntimePins(runtime, pins *measurement.Measurement) error {
	if err := measurement.ValidatePins(pins); err != nil {
		return &errs.ConfigurationError{Err: err}
	}
	if pins == nil {
		return nil
	}
	if pins.Type != runtime.Type || len(pins.Registers) != len(runtime.Registers) {
		return &errs.ConfigurationError{Err: fmt.Errorf("register pins do not match the runtime platform")}
	}
	for i, pin := range pins.Registers {
		if pin != "" && !strings.EqualFold(pin, runtime.Registers[i]) {
			return fmt.Errorf("pinned register %d does not match the runtime manifest", i)
		}
	}
	return nil
}
