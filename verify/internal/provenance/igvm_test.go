package provenance

import (
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// The values below are real: cvmimage publishes them in its v0.15.0-rc6
// manifest and an AMD Turin host reported the SNP one. The predicate carrying
// them is built here, because cvmimage does not emit it yet.
const (
	realTag         = "v0.15.0-rc6"
	realMeasurement = "5b06eeba4725864b09c32b6523a55302cbdb2c3f7f6293bfe492bd92390d1a2abd4db16c454e136c47aed9f61db10df6"
	realMRTD        = "4157242a02f060ebf50854cf8942284a0c34c90b229ff9d171d1c4f70f716a519f61f03603a960f909aeac1a3cf2076e"
	zeroRegister    = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "igvm", name))
	require.NoError(t, err)
	return data
}

// publishedLaunch is what cvmimage's manifest says about v0.15.0-rc6; the
// predicate must carry exactly these values.
func publishedLaunch(t *testing.T) (snp string, tdx map[string]string) {
	t.Helper()
	var manifest struct {
		Version string `json:"version"`
		IGVM    struct {
			SNPLaunch struct {
				Measurement string `json:"measurement"`
			} `json:"snp_launch"`
			TDXLaunch map[string]string `json:"tdx_launch"`
		} `json:"igvm"`
	}
	require.NoError(t, json.Unmarshal(fixture(t, "tinfoil-inference-v0.15.0-rc6-manifest.json"), &manifest))
	require.Equal(t, realTag, manifest.Version)
	return manifest.IGVM.SNPLaunch.Measurement, manifest.IGVM.TDXLaunch
}

// igvmPredicate is the statement cvmimage's release workflow signs: the
// runtime manifest, carried verbatim as the predicate.
func igvmPredicate(t *testing.T, manifest map[string]any) *in_toto.Statement {
	t.Helper()
	predicate, err := structpb.NewStruct(manifest)
	require.NoError(t, err)
	return &in_toto.Statement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: string(measurement.SnpTdxMultiPlatformV2),
		Predicate:     predicate,
	}
}

// publishedManifest is the manifest cvmimage published, as the predicate
// carries it.
func publishedManifest(t *testing.T) map[string]any {
	t.Helper()
	var manifest map[string]any
	require.NoError(t, json.Unmarshal(fixture(t, "tinfoil-inference-v0.15.0-rc6-manifest.json"), &manifest))
	return manifest
}

// launchOf returns the igvm block's two launch objects for mutation.
func launchOf(manifest map[string]any) (map[string]any, map[string]any) {
	igvm := manifest["igvm"].(map[string]any)
	return igvm["snp_launch"].(map[string]any), igvm["tdx_launch"].(map[string]any)
}

// Reads the runtime measurement the way the verifier does, and checks it
// against what cvmimage publishes and what the hardware reported.
func TestIGVMPredicateCarriesTheRealLaunchState(t *testing.T) {
	snp, tdx := publishedLaunch(t)
	assert.Equal(t, realMeasurement, snp, "the manifest and the hardware agree")
	assert.Equal(t, realMRTD, tdx["mrtd"])

	m, err := measurementFromStatement(igvmPredicate(t, publishedManifest(t)))
	require.NoError(t, err)
	assert.Equal(t, measurement.SnpTdxMultiPlatformV2, m.Type)
	require.Len(t, m.Registers, 6, "SNP measurement plus all five TDX registers")
	assert.Equal(t, []string{realMeasurement, realMRTD, zeroRegister, zeroRegister, zeroRegister, zeroRegister}, m.Registers)

	// The report the hardware produced reports exactly that measurement.
	report, err := sevabi.ReportToProto(fixture(t, "sev-snp-report.bin"))
	require.NoError(t, err)
	assert.Equal(t, realMeasurement, hex.EncodeToString(report.GetMeasurement()))
}

// A predicate missing a register would leave it unconstrained.
func TestIGVMPredicateRejections(t *testing.T) {
	for _, name := range []string{"measurement", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"} {
		for _, bad := range []string{"", "ff", strings.ToUpper(realMeasurement)} {
			manifest := publishedManifest(t)
			snp, tdx := launchOf(manifest)
			if name == "measurement" {
				snp[name] = bad
			} else {
				tdx[name] = bad
			}
			_, err := measurementFromStatement(igvmPredicate(t, manifest))
			require.ErrorContains(t, err, name, "%s = %q must reject", name, bad)
		}
	}
	// A manifest with no tdx_launch names no TDX registers at all.
	manifest := publishedManifest(t)
	delete(manifest["igvm"].(map[string]any), "tdx_launch")
	_, err := measurementFromStatement(igvmPredicate(t, manifest))
	require.ErrorContains(t, err, "tdx_launch")
}
