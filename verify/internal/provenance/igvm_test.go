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

// igvmPredicate is the statement cvmimage's release workflow must sign.
func igvmPredicate(t *testing.T, snp string, tdx map[string]string) *in_toto.Statement {
	t.Helper()
	predicate, err := structpb.NewStruct(map[string]any{
		"snp_measurement": snp,
		"tdx_measurement": map[string]any{
			"mrtd": tdx["mrtd"], "rtmr0": tdx["rtmr0"], "rtmr1": tdx["rtmr1"],
			"rtmr2": tdx["rtmr2"], "rtmr3": tdx["rtmr3"],
		},
	})
	require.NoError(t, err)
	return &in_toto.Statement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: string(measurement.IgvmRuntimeV1),
		Predicate:     predicate,
	}
}

// Reads the runtime measurement the way the verifier does, and checks it
// against what cvmimage publishes and what the hardware reported.
func TestIGVMPredicateCarriesTheRealLaunchState(t *testing.T) {
	snp, tdx := publishedLaunch(t)
	assert.Equal(t, realMeasurement, snp, "the manifest and the hardware agree")
	assert.Equal(t, realMRTD, tdx["mrtd"])

	m, err := measurementFromStatement(igvmPredicate(t, snp, tdx))
	require.NoError(t, err)
	assert.Equal(t, measurement.IgvmRuntimeV1, m.Type)
	require.Len(t, m.Registers, 6, "SNP measurement plus all five TDX registers")
	assert.Equal(t, []string{realMeasurement, realMRTD, zeroRegister, zeroRegister, zeroRegister, zeroRegister}, m.Registers)

	// The report the hardware produced reports exactly that measurement.
	report, err := sevabi.ReportToProto(fixture(t, "sev-snp-report.bin"))
	require.NoError(t, err)
	assert.Equal(t, realMeasurement, hex.EncodeToString(report.GetMeasurement()))
}

// A predicate missing a register would leave it unconstrained.
func TestIGVMPredicateRejections(t *testing.T) {
	snp, tdx := publishedLaunch(t)
	for _, name := range []string{"snp_measurement", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"} {
		for _, bad := range []string{"", "ff", strings.ToUpper(realMeasurement)} {
			registers := map[string]string{"mrtd": tdx["mrtd"], "rtmr0": tdx["rtmr0"], "rtmr1": tdx["rtmr1"], "rtmr2": tdx["rtmr2"], "rtmr3": tdx["rtmr3"]}
			value := snp
			if name == "snp_measurement" {
				value = bad
			} else {
				registers[name] = bad
			}
			_, err := measurementFromStatement(igvmPredicate(t, value, registers))
			require.ErrorContains(t, err, name, "%s = %q must reject", name, bad)
		}
	}
	// A predicate with no TDX block names no TDX registers at all.
	bare, err := structpb.NewStruct(map[string]any{"snp_measurement": snp})
	require.NoError(t, err)
	_, err = measurementFromStatement(&in_toto.Statement{
		Type: "https://in-toto.io/Statement/v1", PredicateType: string(measurement.IgvmRuntimeV1), Predicate: bare})
	require.ErrorContains(t, err, "tdx_measurement")
}
