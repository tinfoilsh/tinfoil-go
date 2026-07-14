package quote

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

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

// loadSEVFixture builds a v3 document around a live-captured production
// Genoa report and its VCEK collateral. The captured report predates the v3
// REPORT_DATA ladder, so the expected REPORT_DATA is taken from the report
// itself; the envelope ladder is covered by the envelope package tests.
// Skips when the workspace fixture directory is not present.
func loadSEVFixture(t *testing.T) (*envelope.Document, [64]byte) {
	t.Helper()
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

	reportBytes, err := base64.StdEncoding.DecodeString(fresh.CPU.Report)
	require.NoError(t, err)
	parsedReport, err := sevabi.ReportToProto(reportBytes)
	require.NoError(t, err)
	var reportData [64]byte
	copy(reportData[:], parsedReport.ReportData)

	vcekData, err := json.Marshal(envelope.AMDVCEKCollateral{
		VCEKDERBase64: material.Collateral.CPUVendor.SEVSNP.VCEKDERBase64,
		CertChainPEM:  material.Collateral.CPUVendor.SEVSNP.CertChainPEM,
	})
	require.NoError(t, err)

	return &envelope.Document{
		Format: envelope.AttestationV3Format,
		CPUEvidence: envelope.CPUEvidence{
			Format:       envelope.SEVSNPReportV1Format,
			ReportBase64: fresh.CPU.Report,
		},
		Collateral: []envelope.CollateralEntry{{
			ID:       "cpu-endorsement",
			Role:     envelope.RoleEndorsement,
			Format:   envelope.CollateralAMDVCEKV1Format,
			Subjects: []string{envelope.SubjectCPU},
			Data:     vcekData,
		}},
	}, reportData
}

func loadEndorsementArtifact(t *testing.T) *policy.Artifact {
	t.Helper()
	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.Parse(artifactBytes)
	require.NoError(t, err)
	return artifact
}

// TestVerifySEV runs the v3 SEV path (signature chain, REPORT_DATA binding,
// identity endorsement, appraisal policy) against a live-captured production
// Genoa report wrapped in a v3 document.
func TestVerifySEV(t *testing.T) {
	doc, reportData := loadSEVFixture(t)
	artifact := loadEndorsementArtifact(t)

	// The fixture predates per-release code provenance, so the expected
	// launch measurement is the quote's own; the equality path is still
	// exercised, and the mismatch case is covered below.
	q, err := Authenticate(doc)
	require.NoError(t, err)
	expected := Expected{ReportData: reportData, CodeMeasurement: q.Measurement}

	assembled, verified, err := Verify(doc, expected, artifact)
	require.NoError(t, err)
	assert.Equal(t, policy.PlatformSEVSNP, verified.Platform)
	assert.Equal(t, "amd-genoa-prod", assembled.PolicyName)
	assert.NotEmpty(t, verified.Identity)
	require.NotNil(t, verified.Measurement)
	assert.Equal(t, measurement.SevGuestV2, verified.Measurement.Type)

	// Wrong REPORT_DATA must reject even with a valid signature.
	wrongReportData := expected
	wrongReportData.ReportData[0] ^= 0xff
	_, _, err = Verify(doc, wrongReportData, artifact)
	assert.ErrorContains(t, err, "REPORT_DATA")

	// A launch measurement differing from the code expectation must reject.
	wrongMeasurement := expected
	wrongMeasurement.CodeMeasurement = &measurement.Measurement{
		Type:      measurement.SevGuestV2,
		Registers: []string{strings.Repeat("ab", 48)},
	}
	_, _, err = Verify(doc, wrongMeasurement, artifact)
	assert.Error(t, err)

	// An assembly without the required code expectation must reject.
	_, err = Assemble(artifact, Expected{ReportData: reportData}, q)
	assert.ErrorContains(t, err, "code measurement is required")

	// A machine absent from the artifact must reject.
	unendorsed := *artifact
	unendorsed.Machines = map[string]string{}
	_, _, err = Verify(doc, expected, &unendorsed)
	assert.ErrorContains(t, err, "not endorsed")

	// v3 is single-request: a document without its endorsement collateral is
	// rejected, never patched up with a network fetch.
	noVCEK := *doc
	noVCEK.Collateral = nil
	_, _, err = Verify(&noVCEK, expected, artifact)
	assert.ErrorContains(t, err, "no amd-vcek endorsement collateral")
}

// TestVerifySEVWithCRL exercises the revocation path: the same document with
// an amd-crl collateral entry (CRL fetched live from AMD KDS) must verify
// with revocation checking on, and a garbage CRL must reject.
func TestVerifySEVWithCRL(t *testing.T) {
	if testing.Short() {
		t.Skip("live external services test; skipped with -short")
	}
	doc, reportData := loadSEVFixture(t)
	artifact := loadEndorsementArtifact(t)

	crlBytes, _, err := util.Get("https://kdsintf.amd.com/vcek/v1/Genoa/crl")
	require.NoError(t, err)
	crlData, err := json.Marshal(envelope.AMDCRLCollateral{
		CRLDERBase64: base64.StdEncoding.EncodeToString(crlBytes),
	})
	require.NoError(t, err)
	doc.Collateral = append(doc.Collateral, envelope.CollateralEntry{
		ID:       "cpu-crl",
		Role:     envelope.RoleEndorsement,
		Format:   envelope.CollateralAMDCRLV1Format,
		Subjects: []string{envelope.SubjectCPU},
		Data:     crlData,
	})

	q, err := Authenticate(doc)
	require.NoError(t, err)
	expected := Expected{ReportData: reportData, CodeMeasurement: q.Measurement}

	_, verified, err := Verify(doc, expected, artifact)
	require.NoError(t, err)
	assert.Equal(t, policy.PlatformSEVSNP, verified.Platform)

	// A CRL that does not parse must reject rather than being skipped.
	badCRL, err := json.Marshal(envelope.AMDCRLCollateral{
		CRLDERBase64: base64.StdEncoding.EncodeToString([]byte("not a crl")),
	})
	require.NoError(t, err)
	doc.Collateral[1].Data = badCRL
	_, _, err = Verify(doc, expected, artifact)
	assert.Error(t, err)
}

func TestVerifyUnknownFormat(t *testing.T) {
	doc := &envelope.Document{
		CPUEvidence: envelope.CPUEvidence{Format: "https://tinfoil.sh/format/unknown/v1"},
	}
	_, _, err := Verify(doc, Expected{}, &policy.Artifact{})
	assert.Error(t, err)
	assert.Contains(t, fmt.Sprint(err), "unsupported cpu_evidence format")
}
