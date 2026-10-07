package sev

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/proto"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	sevtestdata "github.com/tinfoilsh/tinfoil-go/verify/internal/testdata"
)

func TestConfigBoundEnforcesConfigAndPlatformConstraints(t *testing.T) {
	const guestPolicy = 0x30133
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
	measurement := hex.EncodeToString(report.Measurement)
	report.Policy = guestPolicy
	p.SEVSNP.MinimumABIVersion = "1.51"
	p.SEVSNP.ConfigBinding = policy.ConfigBindingSHA256
	p.SEVSNP.HostData = ""
	var reportData [64]byte
	copy(reportData[:], report.ReportData)
	_, err = Assemble(p.SEVSNP, q, measurement, reportData)
	require.ErrorContains(t, err, "requires config verification")
	resolved := *p.SEVSNP
	resolved.ConfigBinding = ""
	resolved.HostData = hex.EncodeToString(configHash[:])
	e, err := Assemble(&resolved, q, measurement, reportData)
	require.NoError(t, err)
	require.NoError(t, e.Validate(q))

	// Authentication and appraisal are separate: these mutations exercise the
	// complete appraisal of a quote after the authentication boundary.
	for name, mutate := range map[string]func(*sevsnp.Report){
		"config hash":        func(r *sevsnp.Report) { r.HostData[0] ^= 1 },
		"launch measurement": func(r *sevsnp.Report) { r.Measurement[0] ^= 1 },
		"ABI below floor":    func(r *sevsnp.Report) { r.Policy-- },
		"guest debug":        func(r *sevsnp.Report) { r.Policy |= sevabi.SnpPolicyToBytes(sevabi.SnpPolicy{Debug: true}) },
		"platform state":     func(r *sevsnp.Report) { r.PlatformInfo ^= 1 },
		"family ID":          func(r *sevsnp.Report) { r.FamilyId[0] ^= 1 },
		"image ID":           func(r *sevsnp.Report) { r.ImageId[0] ^= 1 },
		"ID block":           func(r *sevsnp.Report) { r.IdKeyDigest[0] = 1 },
		"versioned ID block": func(r *sevsnp.Report) { r.GuestSvn = 1; r.IdKeyDigest[0] = 1 },
		"report data":        func(r *sevsnp.Report) { r.ReportData[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *q
			bad.attestation = proto.Clone(q.attestation).(*sevsnp.Attestation)
			mutate(bad.attestation.Report)
			require.Error(t, e.Validate(&bad))
		})
	}
	report.Policy++
	require.NoError(t, e.Validate(q), "the platform policy defines an ABI floor")
	legacyPolicy := resolved
	const guestSVNFloor = 1
	legacyPolicy.MinimumGuestSVN = new(uint32(guestSVNFloor))
	legacy, err := Assemble(&legacyPolicy, q, measurement, reportData)
	require.NoError(t, err)
	for _, svn := range []uint32{guestSVNFloor, guestSVNFloor + 1} {
		report.GuestSvn = svn
		require.NoError(t, legacy.Validate(q), "legacy guests accept SVN at or above their endorsed floor")
	}
	report.GuestSvn = guestSVNFloor - 1
	require.Error(t, legacy.Validate(q), "legacy guests reject SVN below their endorsed floor")
	resolved.GuestPolicy.Debug = true
	require.NoError(t, e.Validate(q), "assembled expectations must not alias the platform policy")
}
