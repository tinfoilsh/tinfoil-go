package verify

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/runtime"
)

const (
	capturedPlatformTag    = "v0.0.16"
	capturedPlatformDigest = "c4f46b52976c8d2660f7067fc491eb87c58573671d325b79ef0ca5e97493c40a"
	capturedRuntimeTag     = "v0.15.0-rc6"
	capturedRuntimeDigest  = "3a180dc0d71f30f1d416da805454ae8a677e10697cd093a9bc64ef3918761813"
)

// These published artifacts and the captured Turin report come from
// lothan/verify-igvm-configs at 91d3dcb.
func capturedFixture(t *testing.T, directory, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", directory, name))
	require.NoError(t, err)
	return data
}

func TestCapturedPlatformRejectsConfigBindingMarker(t *testing.T) {
	client, err := endorsement.NewDefaultClient()
	require.NoError(t, err)
	bundle := capturedFixture(t, "igvm", "platform-bundle.json")
	_, err = client.AuthenticatePlatformEndorsements(bundle, freshness.PlatformRepo, capturedPlatformTag, capturedPlatformDigest)
	require.ErrorContains(t, err, "config_binding")
}

func TestCapturedRuntimeMatchesReportMeasurement(t *testing.T) {
	data := capturedFixture(t, "igvm", freshness.RuntimeName(capturedRuntimeTag))
	ref := collateral.RuntimeReference{Repo: collateral.RuntimeRepo, Tag: capturedRuntimeTag, Digest: capturedRuntimeDigest}
	manifest, err := runtime.ParseManifest(data, ref)
	require.NoError(t, err)
	// This fixture has no AMD certificate chain. This checks captured fields,
	// not hardware authentication or runtime build provenance.
	report, err := sevabi.ReportToProto(capturedFixture(t, "igvm", "sev-snp-report.bin"))
	require.NoError(t, err)
	launch := manifest.Measurements.SNPLaunch
	require.Equal(t, launch.Measurement, hex.EncodeToString(report.GetMeasurement()))
}
