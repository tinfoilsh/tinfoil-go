//go:build tinfoil_conformance

package conformance_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/conformance"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

func collateralFixture(t *testing.T, name string) (verify.CollateralCheck, []byte, []byte, []verify.Option) {
	t.Helper()
	dir := os.Getenv("TINFOIL_COLLATERAL_FIXTURES")
	if dir == "" {
		suite := os.Getenv("TINFOIL_CONFORMANCE_FIXTURES")
		if filepath.Base(filepath.Clean(suite)) != "golden" {
			t.Skip("collateral compatibility runs with the shared golden suite")
		}
		dir = filepath.Dir(filepath.Clean(suite))
	}
	data, err := os.ReadFile(filepath.Join(dir, name+".json"))
	require.NoError(t, err)
	var fixture struct{ Input conformance.Input }
	require.NoError(t, json.Unmarshal(data, &fixture))
	in := fixture.Input
	raw, err := base64.StdEncoding.DecodeString(in.DocumentB64)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(in.NonceHex)
	require.NoError(t, err)
	var candidate struct {
		Evidence struct {
			Format string
			Report []byte `json:"report_base64"`
		} `json:"cpu_evidence"`
		Format  string             `json:"collateral_format"`
		Entries []collateral.Entry `json:"collateral"`
	}
	require.NoError(t, json.Unmarshal(raw, &candidate))
	root, err := base64.StdEncoding.DecodeString(in.SigstoreTrustedRootB64)
	require.NoError(t, err)
	var amd, intel []byte
	if in.AMDRootCAPEM != "" {
		amd = []byte(in.ASKPEM + "\n" + in.AMDRootCAPEM)
	}
	if in.IntelSGXRootPEM != "" {
		intel = []byte(in.IntelSGXRootPEM)
	}
	opts := []verify.Option{verify.DangerousTestOnlyWithSigstoreRoot(root), verify.DangerousTestOnlyWithVendorRoots(amd, intel)}
	if in.VerificationTimeUnix != 0 {
		opts = append(opts, verify.DangerousTestOnlyWithClock(func() time.Time { return time.Unix(in.VerificationTimeUnix, 0) }))
	}
	return verify.CollateralCheck{Evidence: document.CPUEvidence{Format: candidate.Evidence.Format, Report: candidate.Evidence.Report}, Format: candidate.Format, Entries: candidate.Entries, Reference: in.Repo}, raw, nonce, opts
}

func TestFixturesCollateralCompatibilitySignedFixtures(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		compatible, attested bool
	}{
		{"golden/golden-happy", true, true},
		{"golden-tdx/tdx-golden-happy", true, true},
		{"golden-tdx/st1-shape-filter", false, false},
		{"golden-tdx/st2-multi-measurement", true, true},
		{"golden-tdx/t14-mrtd", false, false},
		{"golden-tdx/t17-rtmr0", false, false},
		{"golden-tdx/t18-rtmr1", false, false},
		{"golden-tdx/t18-rtmr2", false, false},
		{"golden-tdx/t19-rtmr3", false, false},
		{"golden-tdx/t10-td-attributes", false, false},
		{"golden-tdx/t23-tcb-eval", false, false},
		{"golden/i5-not-endorsed", false, false},
		{"golden/s7-vmpl", false, false},
		{"golden/s14-measurement", false, false},
		{"golden/s19-tcb-floor", false, false},
		{"golden/s13-report-data", true, false},
		{"golden-tdx/t20-report-data", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, raw, nonce, opts := collateralFixture(t, tc.name)
			v, err := verify.NewVerifier(opts...)
			require.NoError(t, err)
			result, err := v.CheckCollateral(candidate)
			if tc.compatible {
				require.NoError(t, err)
				require.True(t, result.WorkloadChecked)
				require.False(t, result.FreshnessExpiresAt.IsZero())
			} else {
				require.Error(t, err)
				require.Nil(t, result)
			}
			_, err = v.VerifyV3(raw, nonce, candidate.Reference)
			if tc.attested {
				require.NoError(t, err)
				nonce[0] ^= 1
				_, err = v.VerifyV3(raw, nonce, candidate.Reference)
				require.ErrorContains(t, err, "nonce")
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestFixturesCollateralCompatibilityRejectsMissingOrDamagedEvidence(t *testing.T) {
	for _, id := range []string{collateral.AMDVCEKV1Format, collateral.AMDCRLV1Format, collateral.SigstoreCodeV1Format, collateral.SigstorePlatformV1Format, collateral.FreshnessIDCode, collateral.FreshnessIDPlatform} {
		t.Run(id, func(t *testing.T) {
			candidate, _, _, opts := collateralFixture(t, "golden/golden-happy")
			kept := candidate.Entries[:0]
			removed := false
			for _, entry := range candidate.Entries {
				if entry.ID == id || entry.Format == id {
					removed = true
				} else {
					kept = append(kept, entry)
				}
			}
			require.True(t, removed)
			candidate.Entries = kept
			v, err := verify.NewVerifier(opts...)
			require.NoError(t, err)
			result, err := v.CheckCollateral(candidate)
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
	candidate, _, _, opts := collateralFixture(t, "golden/golden-happy")
	v, err := verify.NewVerifier(opts...)
	require.NoError(t, err)
	candidate.Evidence.Report[0] ^= 1
	result, err := v.CheckCollateral(candidate)
	require.Error(t, err)
	require.Nil(t, result)
	candidate, _, _, opts = collateralFixture(t, "golden/golden-happy")
	v, err = verify.NewVerifier(opts...)
	require.NoError(t, err)
	accepted, err := v.CheckCollateral(candidate)
	require.NoError(t, err)
	expired := accepted.FreshnessExpiresAt.Add(time.Second)
	opts = append(opts, verify.DangerousTestOnlyWithClock(func() time.Time { return expired }))
	v, err = verify.NewVerifier(opts...)
	require.NoError(t, err)
	result, err = v.CheckCollateral(candidate)
	require.ErrorContains(t, err, "stale")
	require.Nil(t, result)
}

func TestFixturesCollateralRuntimeCheckDoesNotAuthorizePrivateConfig(t *testing.T) {
	candidate, raw, nonce, opts := collateralFixture(t, "golden/golden-happy")
	v, err := verify.NewVerifier(opts...)
	require.NoError(t, err)
	attested, err := v.VerifyV3(raw, nonce, candidate.Reference)
	require.NoError(t, err)
	set, err := document.DecodeCollateral(candidate.Format, candidate.Entries)
	require.NoError(t, err)
	var bundle struct {
		Envelope struct{ Payload []byte } `json:"dsseEnvelope"`
	}
	require.NoError(t, json.Unmarshal(set.SigstorePlatform.Bundle, &bundle))
	var statement struct{ Predicate policy.Artifact }
	require.NoError(t, json.Unmarshal(bundle.Envelope.Payload, &statement))
	platform := statement.Predicate
	platform.Format, platform.Measurements = policy.ArtifactFormatV2, nil
	for name, p := range platform.Policies {
		if p.SEVSNP != nil {
			p.SEVSNP.HostData = ""
		}
		if p.TDX != nil {
			p.TDX.PlatformMeasurements = nil
		}
		platform.Policies[name] = p
	}
	platformBytes, err := json.Marshal(platform)
	require.NoError(t, err)
	const version = "v0.15.0"
	zero := strings.Repeat("00", runtime.MeasurementSize)
	manifest := runtime.Manifest{Version: version, Measurements: &runtime.Measurements{
		FormatVersion: runtime.FormatVersion,
		SNPLaunch:     &runtime.SNPLaunch{Measurement: attested.EnclaveMeasurement.Registers[0]},
		TDXLaunch:     &runtime.TDXLaunch{MRTD: zero, RTMR0: zero, RTMR1: zero, RTMR2: zero, RTMR3: zero},
	}}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	digest := sha256.Sum256(manifestBytes)
	ref := &collateral.RuntimeReference{Repo: collateral.RuntimeRepo, Tag: version, Digest: hex.EncodeToString(digest[:])}
	refs := verify.EmbeddedReferences{Runtime: manifestBytes, Platform: platformBytes}
	v, err = verify.NewVerifier(append(opts, verify.WithEmbeddedReferences(refs))...)
	require.NoError(t, err)
	var cpuEntries []collateral.Entry
	for _, entry := range candidate.Entries {
		if entry.Role == collateral.RoleEndorsement {
			cpuEntries = append(cpuEntries, entry)
		}
	}
	candidate.Format, candidate.Reference, candidate.Runtime, candidate.Entries = collateral.FormatV3, "", ref, cpuEntries
	compatible, err := v.CheckCollateral(candidate)
	require.NoError(t, err)
	require.False(t, compatible.WorkloadChecked)
	require.True(t, compatible.FreshnessExpiresAt.IsZero(), "embedded references do not provide approval freshness")

	badRef := *ref
	badRef.Digest = strings.Repeat("00", sha256.Size)
	candidate.Runtime = &badRef
	_, err = v.CheckCollateral(candidate)
	require.ErrorContains(t, err, "digest pin")
	candidate.Runtime = ref

	manifest.Measurements.SNPLaunch.Measurement = zero
	wrongManifest, err := json.Marshal(manifest)
	require.NoError(t, err)
	wrongDigest := sha256.Sum256(wrongManifest)
	wrongRef := *ref
	wrongRef.Digest = hex.EncodeToString(wrongDigest[:])
	wrongRefs := refs
	wrongRefs.Runtime = wrongManifest
	wrong, err := verify.NewVerifier(append(opts, verify.WithEmbeddedReferences(wrongRefs))...)
	require.NoError(t, err)
	candidate.Runtime = &wrongRef
	compatible, err = wrong.CheckCollateral(candidate)
	require.Error(t, err)
	require.Nil(t, compatible)

	refs.Config = &verify.EmbeddedConfig{Bytes: []byte("cvm-version: " + version + "@sha256:" + ref.Digest + "\n")}
	full, err := verify.NewVerifier(append(opts, verify.WithEmbeddedReferences(refs))...)
	require.NoError(t, err)
	candidate.Runtime = nil
	compatible, err = full.CheckCollateral(candidate)
	require.ErrorContains(t, err, "HOST_DATA")
	require.Nil(t, compatible, "runtime compatibility must not imply a matching private config")
}
