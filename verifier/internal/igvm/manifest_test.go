package igvm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/document/collateral"
)

func validManifest() Manifest {
	zero := uint32(0)
	hash := strings.Repeat("ab", sha256.Size)
	measurement := strings.Repeat("cd", MeasurementSize)
	zeroRegister := strings.Repeat("0", MeasurementSize*2)
	return Manifest{Version: "v0.15.0", Root: hash, Kernel: hash, Initrd: hash, Raw: hash, CVMCompiler: hash, IGVM: &Measurements{
		FormatVersion: FormatVersion, SNP: hash, TDX: hash, Cmdline: "console=ttyS0",
		SNPLaunch: &SNPLaunch{Measurement: measurement, Policy: "0x30133", GuestSVN: &zero, IDKeyDigest: zeroRegister},
		TDXLaunch: &TDXLaunch{MRTD: measurement, RTMR0: zeroRegister, RTMR1: zeroRegister, RTMR2: zeroRegister, RTMR3: zeroRegister},
	}}
}

func manifestBytes(t *testing.T, m Manifest) ([]byte, collateral.RuntimeReference) {
	t.Helper()
	data, err := json.Marshal(m)
	require.NoError(t, err)
	digest := sha256.Sum256(data)
	return data, collateral.RuntimeReference{Repo: collateral.RuntimeRepo, Tag: "v0.15.0", Digest: hex.EncodeToString(digest[:])}
}

func TestManifestRequiresCompleteSupportedMeasurements(t *testing.T) {
	data, ref := manifestBytes(t, validManifest())
	got, err := ParseManifest(data, ref)
	require.NoError(t, err)
	require.Equal(t, validManifest(), *got)
	_, err = ParseManifest(append(data, '\n'), ref)
	require.ErrorContains(t, err, "digest pin")
	for name, mutate := range map[string]func(*Manifest){
		"old manifest":        func(m *Manifest) { m.IGVM = nil },
		"unknown version":     func(m *Manifest) { m.IGVM.FormatVersion++ },
		"wrong release":       func(m *Manifest) { m.Version = "v0.15.1" },
		"missing SNP":         func(m *Manifest) { m.IGVM.SNPLaunch = nil },
		"missing TDX":         func(m *Manifest) { m.IGVM.TDXLaunch = nil },
		"missing SVN":         func(m *Manifest) { m.IGVM.SNPLaunch.GuestSVN = nil },
		"nonzero SVN":         func(m *Manifest) { *m.IGVM.SNPLaunch.GuestSVN = 1 },
		"ID block":            func(m *Manifest) { m.IGVM.SNPLaunch.IDKeyDigest = strings.Repeat("ab", MeasurementSize) },
		"nonzero RTMR":        func(m *Manifest) { m.IGVM.TDXLaunch.RTMR2 = strings.Repeat("ab", MeasurementSize) },
		"missing RTMR":        func(m *Manifest) { m.IGVM.TDXLaunch.RTMR3 = "" },
		"missing cmdline":     func(m *Manifest) { m.IGVM.Cmdline = "" },
		"bad MRTD":            func(m *Manifest) { m.IGVM.TDXLaunch.MRTD = "bad" },
		"uppercase digest":    func(m *Manifest) { m.IGVM.SNP = strings.ToUpper(m.IGVM.SNP) },
		"decimal policy":      func(m *Manifest) { m.IGVM.SNPLaunch.Policy = "196915" },
		"noncanonical policy": func(m *Manifest) { m.IGVM.SNPLaunch.Policy = "0x030133" },
	} {
		t.Run(name, func(t *testing.T) {
			m := validManifest()
			mutate(&m)
			data, ref := manifestBytes(t, m)
			_, err := ParseManifest(data, ref)
			require.Error(t, err)
		})
	}
	for name, prefix := range map[string]string{"unknown member": `{"unknown":true,`, "duplicate member": `{"version":"v0.15.0",`} {
		t.Run(name, func(t *testing.T) {
			changed := append([]byte(prefix), data[1:]...)
			digest := sha256.Sum256(changed)
			pinned := ref
			pinned.Digest = hex.EncodeToString(digest[:])
			_, err := ParseManifest(changed, pinned)
			require.ErrorContains(t, err, "parsing runtime manifest")
		})
	}
}

func TestConfigRuntimePin(t *testing.T) {
	digest := strings.Repeat("ab", sha256.Size)
	for _, version := range []string{"0.15.0", "v0.15.0", "0.15.0-rc.1"} {
		config := []byte("cvm-version: " + version + "@sha256:" + digest + "\ncontainers: []\n")
		ref, err := ConfigRuntime(config)
		require.NoError(t, err)
		require.Equal(t, collateral.RuntimeReference{Repo: collateral.RuntimeRepo, Tag: "v" + strings.TrimPrefix(version, "v"), Digest: digest}, ref)
	}
	good := "cvm-version: 0.15.0@sha256:" + digest + "\n"
	for name, config := range map[string]string{
		"unpinned":         "cvm-version: 0.15.0\n",
		"duplicate":        good + good,
		"two documents":    good + "---\n" + good,
		"alternate repo":   good + "cvm-source: {repo: other/runtime, artifacts: https://images.tinfoil.sh/cvm}\n",
		"alternate source": good + "cvm-source: {repo: tinfoilsh/cvmimage, artifacts: https://other.example}\n",
		"bad digest":       strings.ReplaceAll(good, digest, strings.ToUpper(digest)),
		"build suffix":     strings.ReplaceAll(good, "0.15.0", "0.15.0+build"),
		"missing version":  "containers: []\n",
	} {
		t.Run(name, func(t *testing.T) { _, err := ConfigRuntime([]byte(config)); require.Error(t, err) })
	}
}
