package sev

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/proto"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/igvm"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	sevtestdata "github.com/tinfoilsh/tinfoil-go/verify/internal/testdata"
)

func TestIGVMEnforcesConfigAndPlatformConstraints(t *testing.T) {
	raw, err := sevtestdata.Box2TurinReport()
	require.NoError(t, err)
	report, err := sevabi.ReportToProto(raw)
	require.NoError(t, err)
	vcek, err := sevtestdata.Box2TurinVcek()
	require.NoError(t, err)
	product, err := productFromReport(report)
	require.NoError(t, err)
	identity, err := Identity(report.GetChipId())
	require.NoError(t, err)
	q := &Quote{identity: identity, attestation: &sevsnp.Attestation{Report: report, CertificateChain: &sevsnp.CertificateChain{VcekCert: vcek}, Product: product}}
	_, p, err := loadFixture(t).PolicyFor(identity, policy.PlatformSEVSNP)
	require.NoError(t, err)
	configHash := sha256.Sum256([]byte("approved YAML bytes"))
	report.HostData = append([]byte(nil), configHash[:]...)
	runtime := &igvm.SNPLaunch{Measurement: hex.EncodeToString(report.Measurement), Policy: "0x" + strconv.FormatUint(report.Policy, 16), GuestSVN: ptr(uint32(0))}
	p.SEVSNP.ConfigBinding = policy.ConfigBindingSHA256
	p.SEVSNP.HostData = ""
	var reportData [64]byte
	copy(reportData[:], report.ReportData)
	_, err = Assemble(p.SEVSNP, q, runtime.Measurement, reportData)
	require.ErrorContains(t, err, "requires IGVM")
	e, err := AssembleIGVM(p.SEVSNP, q, runtime, configHash, reportData)
	require.NoError(t, err)
	require.NoError(t, e.Validate(q))

	// Authentication and appraisal are separate: these mutations exercise the
	// complete appraisal of a quote after the authentication boundary.
	for name, mutate := range map[string]func(*sevsnp.Report){
		"config hash":        func(r *sevsnp.Report) { r.HostData[0] ^= 1 },
		"launch measurement": func(r *sevsnp.Report) { r.Measurement[0] ^= 1 },
		"guest SVN":          func(r *sevsnp.Report) { r.GuestSvn = 1 },
		"guest policy":       func(r *sevsnp.Report) { r.Policy ^= 1 },
		"platform state":     func(r *sevsnp.Report) { r.PlatformInfo ^= 1 },
		"family ID":          func(r *sevsnp.Report) { r.FamilyId[0] ^= 1 },
		"image ID":           func(r *sevsnp.Report) { r.ImageId[0] ^= 1 },
		"ID block":           func(r *sevsnp.Report) { r.IdKeyDigest[0] = 1 },
		"report data":        func(r *sevsnp.Report) { r.ReportData[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *q
			bad.attestation = proto.Clone(q.attestation).(*sevsnp.Attestation)
			mutate(bad.attestation.Report)
			require.Error(t, e.Validate(&bad))
		})
	}
	badRuntime := *runtime
	badRuntime.Policy = "0x30133"
	if badRuntime.Policy == runtime.Policy {
		badRuntime.Policy = "0x30132"
	}
	e, err = AssembleIGVM(p.SEVSNP, q, &badRuntime, configHash, reportData)
	require.NoError(t, err)
	require.Error(t, e.Validate(q))
	p.SEVSNP.ConfigBinding = ""
	_, err = AssembleIGVM(p.SEVSNP, q, runtime, configHash, reportData)
	require.ErrorContains(t, err, "config-binding")
}
