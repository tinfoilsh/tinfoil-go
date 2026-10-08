package quote

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
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
	_, err := Assemble(doc, ConfigReferenceValues{Endorsements: &policy.Artifact{}, Runtime: &runtime.Measurements{}}, nil, q)
	require.ErrorContains(t, err, "not this document's CPU evidence")
}

func TestConfigPreparationResolvesRuntimeAndHash(t *testing.T) {
	for _, platform := range []string{policy.PlatformSEVSNP, policy.PlatformTDX} {
		t.Run(platform, func(t *testing.T) {
			artifact := loadEndorsementArtifact(t)
			q := &Authenticated{platform: platform, sev: &sev.Quote{}, tdx: &tdx.Quote{}}
			for identity, name := range artifact.Machines {
				if artifact.Policies[name].Platform == platform {
					q.identity = identity
					break
				}
			}
			require.NotEmpty(t, q.identity)
			register := strings.Repeat("ab", runtime.MeasurementSize)
			zero := strings.Repeat("0", runtime.MeasurementSize*2)
			hash := sha256.Sum256([]byte("endorsed config bytes"))
			refs := ConfigReferenceValues{Endorsements: artifact, Hash: hash, Runtime: &runtime.Measurements{
				FormatVersion: runtime.FormatVersion,
				SNPLaunch:     &runtime.SNPLaunch{Measurement: register},
				TDXLaunch:     &runtime.TDXLaunch{MRTD: register, RTMR0: zero, RTMR1: zero, RTMR2: zero, RTMR3: zero},
			}}
			_, err := refs.resolve(q, nil)
			require.ErrorContains(t, err, "cannot be combined with platform")
			_, p, err := artifact.PolicyFor(q.identity, platform)
			require.NoError(t, err)
			if platform == policy.PlatformSEVSNP {
				p.SEVSNP.HostData = ""
			} else {
				p.TDX.PlatformMeasurements = nil
			}
			resolved, err := refs.resolve(q, nil)
			require.NoError(t, err)
			if platform == policy.PlatformSEVSNP {
				require.Equal(t, hex.EncodeToString(hash[:]), resolved.hostData)
				require.Equal(t, []string{register}, resolved.registers)
				require.Empty(t, p.SEVSNP.HostData, "preparation must not modify platform endorsements")
			} else {
				require.Equal(t, hash[:], resolved.configID[:sha256.Size])
				require.Equal(t, make([]byte, len(resolved.configID)-sha256.Size), resolved.configID[sha256.Size:])
				require.Equal(t, []string{register, zero, zero, zero, zero}, resolved.registers)
			}
			pins := &measurement.Measurement{Type: resolved.code.Type, Registers: append([]string(nil), resolved.registers...)}
			pins.Registers[0] = strings.Repeat("cd", runtime.MeasurementSize)
			_, err = refs.resolve(q, pins)
			require.ErrorContains(t, err, "does not match")
			refs.Runtime.SNPLaunch.Measurement = "changed"
			refs.Runtime.TDXLaunch.MRTD = "changed"
			require.Equal(t, register, resolved.registers[0])
		})
	}
}
