package policy

import (
	"crypto/sha256"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlatformPolicyWithoutWorkloadMeasurements(t *testing.T) {
	artifact := loadFixture(t)
	artifact.Format = ArtifactFormatV2
	artifact.Measurements = nil
	for _, p := range artifact.Policies {
		if p.SEVSNP != nil {
			p.SEVSNP.HostData = ""
		} else {
			p.TDX.PlatformMeasurements = nil
		}
	}
	data, err := json.Marshal(artifact)
	require.NoError(t, err)
	require.NotContains(t, string(data), `"measurements"`)
	parsed, err := Parse(data)
	require.NoError(t, err)
	require.Equal(t, artifact, parsed)
	for name, mutate := range map[string]func(*Artifact){
		"v1 requires workload measurements": func(a *Artifact) { a.Format = ArtifactFormat },
		"v2 excludes host_data": func(a *Artifact) {
			for _, p := range a.Policies {
				if p.SEVSNP != nil {
					p.SEVSNP.HostData = strings.Repeat("00", sha256.Size)
				}
			}
		},
		"v2 excludes platform_measurements": func(a *Artifact) {
			for _, p := range a.Policies {
				if p.TDX != nil {
					p.TDX.PlatformMeasurements = []string{"legacy"}
				}
			}
		},
		"v2 excludes measurement map": func(a *Artifact) {
			a.Measurements = map[string]PlatformMeasurement{"legacy": {}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed Artifact
			require.NoError(t, json.Unmarshal(data, &changed))
			mutate(&changed)
			require.NotEqual(t, artifact, &changed)
			encoded, err := json.Marshal(changed)
			require.NoError(t, err)
			_, err = Parse(encoded)
			require.Error(t, err)
		})
	}

	for _, block := range []string{"sev_snp", "tdx"} {
		var marked map[string]any
		require.NoError(t, json.Unmarshal(data, &marked))
		for _, p := range marked["policies"].(map[string]any) {
			if fields, ok := p.(map[string]any)[block].(map[string]any); ok {
				fields["config_binding"] = "sha256"
			}
		}
		encoded, err := json.Marshal(marked)
		require.NoError(t, err)
		_, err = Parse(encoded)
		require.ErrorContains(t, err, "config_binding")
	}
}
