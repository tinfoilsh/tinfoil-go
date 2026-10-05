package quote

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestIGVMRuntimePinsCannotOverrideMeasurements(t *testing.T) {
	register := strings.Repeat("ab", igvm.MeasurementSize)
	runtime := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{register, register, register, register, register}}
	pins := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{"", "", strings.ToUpper(register), "", ""}}
	got, err := applyPins(runtime.Registers, runtime.Type, pins)
	require.NoError(t, err)
	require.Equal(t, []string{register, register, register, register, register}, got)
	pins.Registers[2] = strings.Repeat("cd", igvm.MeasurementSize)
	_, err = applyPins(runtime.Registers, runtime.Type, pins)
	require.ErrorContains(t, err, "does not match")
	pins = &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{register}}
	_, err = applyPins(runtime.Registers, runtime.Type, pins)
	require.Error(t, err)
}

func TestIGVMAssemblyRequiresMatchingAuthenticatedEvidence(t *testing.T) {
	doc := boundDocument(t, []byte("document quote"))
	q := &Authenticated{platform: policy.PlatformSEVSNP, evidence: doc.CPUEvidence()}
	q.evidence.Report = []byte("substituted quote")
	_, err := AssembleIGVM(doc, &policy.Artifact{}, &igvm.Measurements{}, nil, [32]byte{}, q)
	require.ErrorContains(t, err, "not this document's CPU evidence")
}
