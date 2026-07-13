package attestation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sevabi "github.com/google/go-sev-guest/abi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// TestVerifyCPUEvidenceV3SEV runs the v3 SEV evidence path (signature chain,
// REPORT_DATA binding, identity endorsement, appraisal policy) against a
// live-captured production Genoa report wrapped in a v3 document. The
// captured report predates the v3 REPORT_DATA ladder, so the expected
// REPORT_DATA is taken from the report itself; the envelope ladder is
// covered separately by the builder round-trip tests. Skips when the
// workspace fixture directory is not present.
func TestVerifyCPUEvidenceV3SEV(t *testing.T) {
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
			Report string `json:"report"`
		} `json:"cpu"`
	}
	require.NoError(t, json.Unmarshal(freshBytes, &fresh))

	var material struct {
		Collateral struct {
			CPUVendor struct {
				SEVSNP struct {
					VCEKDERBase64 string `json:"vcek_der_base64"`
					CertChainPEM  string `json:"cert_chain_pem"`
				} `json:"sev_snp"`
			} `json:"cpu_vendor"`
		} `json:"collateral"`
	}
	require.NoError(t, json.Unmarshal(materialBytes, &material))

	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.ParseArtifact(artifactBytes)
	require.NoError(t, err)

	reportBytes, err := base64.StdEncoding.DecodeString(fresh.CPU.Report)
	require.NoError(t, err)
	parsedReport, err := sevabi.ReportToProto(reportBytes)
	require.NoError(t, err)
	var reportData [64]byte
	copy(reportData[:], parsedReport.ReportData)

	vcekData, err := json.Marshal(AMDVCEKCollateral{
		VCEKDERBase64: material.Collateral.CPUVendor.SEVSNP.VCEKDERBase64,
		CertChainPEM:  material.Collateral.CPUVendor.SEVSNP.CertChainPEM,
	})
	require.NoError(t, err)

	doc := &DocumentV3{
		Format: AttestationV3Format,
		CPUEvidence: CPUEvidenceV3{
			Format:       SEVSNPReportV1Format,
			ReportBase64: fresh.CPU.Report,
		},
		Collateral: []CollateralEntry{{
			ID:       "cpu-endorsement",
			Role:     RoleEndorsement,
			Format:   CollateralAMDVCEKV1Format,
			Subjects: []string{SubjectCPU},
			Data:     vcekData,
		}},
	}

	// The fixture predates per-release code provenance, so the expected
	// launch measurement is the quote's own; the equality path is still
	// exercised, and the mismatch case is covered below.
	quote, err := AuthenticateQuoteV3(doc)
	require.NoError(t, err)
	expected := ExpectedValues{ReportData: reportData, CodeMeasurement: quote.Measurement}

	evidence, err := VerifyCPUEvidenceV3(doc, expected, artifact)
	require.NoError(t, err)
	assert.Equal(t, policy.PlatformSEVSNP, evidence.Platform)
	assert.Equal(t, "amd-genoa-prod", evidence.PolicyName)
	assert.NotEmpty(t, evidence.PlatformIdentity)
	require.NotNil(t, evidence.Measurement)
	assert.Equal(t, SevGuestV2, evidence.Measurement.Type)

	// Wrong REPORT_DATA must reject even with a valid signature.
	wrongReportData := expected
	wrongReportData.ReportData[0] ^= 0xff
	_, err = VerifyCPUEvidenceV3(doc, wrongReportData, artifact)
	assert.ErrorContains(t, err, "REPORT_DATA")

	// A launch measurement differing from the code expectation must reject.
	wrongMeasurement := expected
	wrongMeasurement.CodeMeasurement = &Measurement{
		Type:      SevGuestV2,
		Registers: []string{strings.Repeat("ab", 48)},
	}
	_, err = VerifyCPUEvidenceV3(doc, wrongMeasurement, artifact)
	assert.Error(t, err)

	// An assembly without the required code expectation must reject.
	_, err = AssemblePolicyV3(artifact, ExpectedValues{ReportData: reportData}, quote)
	assert.ErrorContains(t, err, "code measurement is required")

	// A machine absent from the artifact must reject.
	unendorsed := *artifact
	unendorsed.Machines = map[string]string{}
	_, err = VerifyCPUEvidenceV3(doc, expected, &unendorsed)
	assert.ErrorContains(t, err, "not endorsed")

	// v3 is single-request: a document without its endorsement collateral is
	// rejected, never patched up with a network fetch.
	noVCEK := *doc
	noVCEK.Collateral = nil
	_, err = VerifyCPUEvidenceV3(&noVCEK, expected, artifact)
	assert.ErrorContains(t, err, "no amd-vcek endorsement collateral")
}

func TestVerifyCPUEvidenceV3UnknownFormat(t *testing.T) {
	doc := &DocumentV3{
		CPUEvidence: CPUEvidenceV3{Format: "https://tinfoil.sh/format/unknown/v1"},
	}
	_, err := VerifyCPUEvidenceV3(doc, ExpectedValues{}, &policy.Artifact{})
	assert.Error(t, err)
	assert.Contains(t, fmt.Sprint(err), "unsupported cpu_evidence format")
}
