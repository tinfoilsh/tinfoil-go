package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func validManifest() Manifest {
	measurement := strings.Repeat("cd", MeasurementSize)
	zeroRegister := strings.Repeat("0", MeasurementSize*2)
	return Manifest{Version: "v0.15.0", Measurements: &Measurements{
		FormatVersion: FormatVersion,
		SNPLaunch:     &SNPLaunch{Measurement: measurement},
		TDXLaunch:     &TDXLaunch{MRTD: measurement, RTMR0: zeroRegister, RTMR1: zeroRegister, RTMR2: zeroRegister, RTMR3: zeroRegister},
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
		"old manifest":    func(m *Manifest) { m.Measurements = nil },
		"unknown version": func(m *Manifest) { m.Measurements.FormatVersion++ },
		"wrong release":   func(m *Manifest) { m.Version = "v0.15.1" },
		"missing SNP":     func(m *Manifest) { m.Measurements.SNPLaunch = nil },
		"missing TDX":     func(m *Manifest) { m.Measurements.TDXLaunch = nil },
		"nonzero RTMR":    func(m *Manifest) { m.Measurements.TDXLaunch.RTMR2 = strings.Repeat("ab", MeasurementSize) },
		"missing RTMR":    func(m *Manifest) { m.Measurements.TDXLaunch.RTMR3 = "" },
		"bad MRTD":        func(m *Manifest) { m.Measurements.TDXLaunch.MRTD = "bad" },
		"uppercase SNP": func(m *Manifest) {
			m.Measurements.SNPLaunch.Measurement = strings.ToUpper(m.Measurements.SNPLaunch.Measurement)
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := validManifest()
			mutate(&m)
			data, ref := manifestBytes(t, m)
			_, err := ParseManifest(data, ref)
			require.Error(t, err)
		})
	}
	for name, tc := range map[string]struct {
		prefix  string
		wantErr bool
	}{
		"download metadata":        {`{"root":"host image digest",`, false},
		"duplicate member":         {`{"version":"v0.15.0",`, true},
		"duplicate ignored member": {`{"root":"one","root":"two",`, true},
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]byte(tc.prefix), data[1:]...)
			digest := sha256.Sum256(changed)
			pinned := ref
			pinned.Digest = hex.EncodeToString(digest[:])
			got, err := ParseManifest(changed, pinned)
			if tc.wantErr {
				require.ErrorContains(t, err, "parsing runtime manifest")
			} else {
				require.NoError(t, err)
				require.Equal(t, validManifest(), *got)
				_, err = ParseManifest(changed, ref)
				require.ErrorContains(t, err, "digest pin")
			}
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
		"unpinned":        "cvm-version: 0.15.0\n",
		"duplicate":       good + good,
		"two documents":   good + "---\n" + good,
		"bad digest":      strings.ReplaceAll(good, digest, strings.ToUpper(digest)),
		"build suffix":    strings.ReplaceAll(good, "0.15.0", "0.15.0+build"),
		"missing version": "containers: []\n",
	} {
		t.Run(name, func(t *testing.T) { _, err := ConfigRuntime([]byte(config)); require.Error(t, err) })
	}
}

func TestManifestVariantSelection(t *testing.T) {
	cpu, gpu := validManifest().Measurements, validManifest().Measurements
	gpu.SNPLaunch.Measurement = strings.Repeat("ef", MeasurementSize)
	gpu.TDXLaunch.MRTD = strings.Repeat("12", MeasurementSize)
	m := Manifest{Version: "v0.15.0", Measurements: &Measurements{FormatVersion: VariantFormatVersion,
		Variants: map[string]*VariantMeasurements{
			"cpu": {SNPLaunch: cpu.SNPLaunch, TDXLaunch: cpu.TDXLaunch},
			"gpu": {SNPLaunch: gpu.SNPLaunch, TDXLaunch: gpu.TDXLaunch},
		},
	}}
	m.Measurements.Variants["initrd"] = &VariantMeasurements{}
	data, ref := manifestBytes(t, m)
	for selector, want := range map[string]*Measurements{"": cpu, "gpu": gpu} {
		ref.Variant = selector
		parsed, err := ParseManifest(data, ref)
		require.NoError(t, err)
		selected, err := parsed.SelectVariant(selector)
		require.NoError(t, err)
		require.Equal(t, want.SNPLaunch, selected.SNPLaunch)
		require.Equal(t, want.TDXLaunch, selected.TDXLaunch)
	}
	for _, selector := range []string{"cpu", "initrd", "GPU"} {
		ref.Variant = selector
		_, err := ParseManifest(data, ref)
		require.Error(t, err)
	}
	legacy, legacyRef := manifestBytes(t, validManifest())
	legacyRef.Variant = "gpu"
	_, err := ParseManifest(legacy, legacyRef)
	require.ErrorContains(t, err, "v1 does not support")
	for name, mutate := range map[string]func(*Manifest){
		"missing CPU":        func(m *Manifest) { delete(m.Measurements.Variants, "cpu") },
		"missing GPU":        func(m *Manifest) { m.Measurements.Variants["gpu"] = nil },
		"mixed layouts":      func(m *Manifest) { m.Measurements.SNPLaunch = cpu.SNPLaunch },
		"incomplete variant": func(m *Manifest) { m.Measurements.Variants["gpu"].TDXLaunch = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var invalid Manifest
			require.NoError(t, json.Unmarshal(data, &invalid))
			mutate(&invalid)
			bytes, pin := manifestBytes(t, invalid)
			_, err := ParseManifest(bytes, pin)
			require.Error(t, err)
		})
	}
}
