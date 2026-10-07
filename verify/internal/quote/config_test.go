package quote

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestConfigBoundRuntimePinsCannotOverrideMeasurements(t *testing.T) {
	register := strings.Repeat("ab", runtime.MeasurementSize)
	measured := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{register, register, register, register, register}}
	pins := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{"", "", strings.ToUpper(register), "", ""}}
	got, err := applyPins(measured.Registers, measured.Type, pins)
	require.NoError(t, err)
	require.Equal(t, []string{register, register, register, register, register}, got)
	pins.Registers[2] = strings.Repeat("cd", runtime.MeasurementSize)
	_, err = applyPins(measured.Registers, measured.Type, pins)
	require.ErrorContains(t, err, "does not match")
	pins = &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{register}}
	_, err = applyPins(measured.Registers, measured.Type, pins)
	require.Error(t, err)
}

func TestConfigBoundAssemblyRequiresMatchingAuthenticatedEvidence(t *testing.T) {
	doc := boundDocument(t, []byte("document quote"))
	q := &Authenticated{platform: policy.PlatformSEVSNP, evidence: doc.CPUEvidence()}
	q.evidence.Report = []byte("substituted quote")
	_, err := Assemble(doc, ReferenceValues{Endorsements: &policy.Artifact{}, Config: &ConfigReferenceValues{Runtime: &runtime.Measurements{}}}, nil, q)
	require.ErrorContains(t, err, "not this document's CPU evidence")
}

func TestConfigAssemblyRejectsPlatformHostData(t *testing.T) {
	artifact := loadEndorsementArtifact(t)
	for identity, name := range artifact.Machines {
		if artifact.Policies[name].SEVSNP == nil {
			continue
		}
		q := &Authenticated{platform: policy.PlatformSEVSNP, identity: identity, sev: &sev.Quote{}}
		refs := ReferenceValues{Endorsements: artifact, Config: &ConfigReferenceValues{Runtime: &runtime.Measurements{
			SNPLaunch: &runtime.SNPLaunch{Measurement: strings.Repeat("ab", runtime.MeasurementSize)},
			TDXLaunch: &runtime.TDXLaunch{},
		}}}
		_, err := assemble(refs, nil, [64]byte{}, q)
		require.ErrorContains(t, err, "cannot be combined with platform host_data")
		return
	}
	t.Fatal("fixture contains no SEV-SNP machine")
}
