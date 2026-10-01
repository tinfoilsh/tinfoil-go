package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigBindingPoliciesExcludeLegacyMeasurementSources(t *testing.T) {
	sev := validSEVSNPPolicy()
	sev.ConfigBinding = ConfigBindingSHA256
	require.ErrorContains(t, sev.Validate(), "excludes host_data")
	sev.HostData = ""
	require.NoError(t, sev.Validate())
	sev.ConfigBinding = "unknown"
	require.Error(t, sev.Validate())
	tdx := validTDXPolicy()
	tdx.ConfigBinding = ConfigBindingSHA256
	require.ErrorContains(t, tdx.Validate(), "excludes platform_measurements")
	tdx.PlatformMeasurements = nil
	require.NoError(t, tdx.Validate())
	tdx.ConfigBinding = "unknown"
	require.Error(t, tdx.Validate())
}
