package attestation

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// TestVerifySevReportWithEndorsements runs the full endorsement-enforced
// verification against a live-captured production report (a Genoa machine
// endorsed in the artifact) plus the real machines/policies data. Skips when
// the workspace fixture directory is not present.
func TestVerifySevReportWithEndorsements(t *testing.T) {
	root := filepath.Join("..", "..", "..", "attestation-samples", "inference.tinfoil.sh")
	freshBytes, err := os.ReadFile(filepath.Join(root, "fresh.json"))
	if os.IsNotExist(err) {
		t.Skip("live inference fixture not collected")
	}
	require.NoError(t, err)
	materialBytes, err := os.ReadFile(filepath.Join(root, "attestation-material.json"))
	require.NoError(t, err)

	var fresh struct {
		CPU struct {
			Platform string `json:"platform"`
			Report   string `json:"report"`
		} `json:"cpu"`
	}
	require.NoError(t, json.Unmarshal(freshBytes, &fresh))
	require.Equal(t, "sev-snp", fresh.CPU.Platform)

	var material struct {
		Collateral struct {
			CPUVendor struct {
				SEVSNP struct {
					VCEKDERBase64 string `json:"vcek_der_base64"`
				} `json:"sev_snp"`
			} `json:"cpu_vendor"`
		} `json:"collateral"`
	}
	require.NoError(t, json.Unmarshal(materialBytes, &material))
	vcekDER := mustBase64(t, material.Collateral.CPUVendor.SEVSNP.VCEKDERBase64)

	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.ParseArtifact(artifactBytes)
	require.NoError(t, err)

	report, policyName, err := verifySevReportWithEndorsements(fresh.CPU.Report, vcekDER, artifact)
	require.NoError(t, err)
	assert.Equal(t, "amd-genoa-prod", policyName)
	assert.NotEmpty(t, report.Measurement)

	// The same quote must fail against an artifact that does not endorse
	// this machine.
	unendorsed := *artifact
	unendorsed.Machines = map[string]string{}
	_, _, err = verifySevReportWithEndorsements(fresh.CPU.Report, vcekDER, &unendorsed)
	assert.ErrorContains(t, err, "not endorsed")
}

func mustBase64(t *testing.T, s string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return decoded
}
