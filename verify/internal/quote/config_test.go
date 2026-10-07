package quote

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
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

func TestConfigResolutionPreservesItsSources(t *testing.T) {
	p := loadEndorsementArtifact(t).Policies["amd-turin-prod"].SEVSNP
	p.ConfigBinding, p.HostData = policy.ConfigBindingSHA256, ""
	hash := sha256.Sum256([]byte("approved config"))
	config := ConfigReferenceValues{Hash: hash}
	resolved, err := config.resolveSEV(p)
	require.NoError(t, err)
	require.Empty(t, resolved.ConfigBinding)
	require.Equal(t, hex.EncodeToString(hash[:]), resolved.HostData)
	require.Equal(t, policy.ConfigBindingSHA256, p.ConfigBinding)
	require.Empty(t, p.HostData)
	config.Hash[0] ^= 1
	require.Equal(t, hex.EncodeToString(hash[:]), resolved.HostData)
	p.ConfigBinding = ""
	_, err = config.resolveSEV(p)
	require.ErrorContains(t, err, "config-binding")
}
