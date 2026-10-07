package policy

import (
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlatformPolicyWithoutWorkloadMeasurements(t *testing.T) {
	artifact := loadFixture(t)
	artifact.Format = ArtifactFormatV2
	artifact.Measurements = map[string]PlatformMeasurement{}
	for _, p := range artifact.Policies {
		if p.SEVSNP != nil {
			p.SEVSNP.HostData = ""
		} else {
			p.TDX.PlatformMeasurements = nil
		}
	}
	data, err := json.Marshal(artifact)
	require.NoError(t, err)
	parsed, err := Parse(data)
	require.NoError(t, err)
	require.Equal(t, artifact, parsed)
	for name, changed := range map[string]string{
		"v1 requires workload measurements": strings.Replace(string(data), ArtifactFormatV2, ArtifactFormat, 1),
		"v2 excludes host_data":             strings.Replace(string(data), `"sev_snp":{`, `"sev_snp":{"host_data":"`+strings.Repeat("00", 32)+`",`, 1),
		"v2 excludes platform_measurements": strings.Replace(string(data), `"tdx":{`, `"tdx":{"platform_measurements":["legacy"],`, 1),
		"v2 excludes measurement map":       strings.Replace(string(data), `"measurements":{}`, `"measurements":{"legacy":{}}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, string(data), changed)
			_, err := Parse([]byte(changed))
			require.Error(t, err)
		})
	}

	for _, block := range []string{"sev_snp", "tdx"} {
		marked := strings.Replace(string(data), `"`+block+`":{`, `"`+block+`":{"config_binding":"sha256",`, 1)
		require.NotEqual(t, string(data), marked)
		_, err := Parse([]byte(marked))
		require.ErrorContains(t, err, "config_binding")
	}
}
