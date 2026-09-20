package quote

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

// testShape is an arbitrary required shape for paths that do not consume it
// (SEV assembly).
var testShape = &policy.Shape{CPUs: 1, MemoryMB: 1, Disks: 1}

// loadSEVFixture builds a v3 document around a live-captured production
// Genoa report, its VCEK collateral, and a live-fetched AMD CRL (captured
// documents predate the amd-crl entry). The captured report predates the v3
// REPORT_DATA ladder, so the expected REPORT_DATA is taken from the report
// itself; the envelope ladder is covered by the envelope package tests.
// Skips when the workspace fixture directory is not present or with -short.
func loadSEVFixture(t *testing.T) (*envelope.Document, [64]byte) {
	t.Helper()
	if testing.Short() {
		t.Skip("fetches the AMD CRL live; skipped with -short")
	}
	root := filepath.Join("..", "..", "..", "..", "attestation-samples", "inference.tinfoil.sh")
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

	doc := &envelope.Document{
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
	}
	appendLiveCRL(t, doc)
	return doc, reportData
}

// appendLiveCRL fetches the AMD CRL missing from older fixtures.
func appendLiveCRL(t *testing.T, doc *envelope.Document) {
	t.Helper()
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
}

func loadEndorsementArtifact(t *testing.T) *policy.Artifact {
	t.Helper()
	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.Parse(artifactBytes)
	require.NoError(t, err)
	return artifact
}

func TestVerifySEV(t *testing.T) {
	doc, reportData := loadSEVFixture(t)
	artifact := loadEndorsementArtifact(t)

	// The fixture has no code provenance, so use its observed launch measurement.
	q, err := Authenticate(doc)
	require.NoError(t, err)
	assembled, verified, err := Verify(doc, artifact, asCode(q.Measurement), nil, testShape, reportData)
	require.NoError(t, err)
	assert.Equal(t, policy.PlatformSEVSNP, verified.Platform())
	assert.Equal(t, "amd-genoa-prod", assembled.PolicyName)
	assert.NotEmpty(t, verified.Identity())
	require.NotNil(t, verified.Measurement)
	assert.Equal(t, measurement.SevGuestV2, verified.Measurement.Type)
	*verified = Authenticated{}
	require.NoError(t, assembled.Validate(), "assembly must retain its original authenticated quote")

	// Wrong REPORT_DATA must reject even with a valid signature.
	wrongReportData := reportData
	wrongReportData[0] ^= 0xff
	_, _, err = Verify(doc, artifact, asCode(q.Measurement), nil, testShape, wrongReportData)
	assert.ErrorContains(t, err, "REPORT_DATA")

	// A launch measurement differing from the code expectation must reject.
	wrongMeasurement := asCode(q.Measurement)
	wrongMeasurement.Registers[0] = strings.Repeat("ab", 48)
	_, _, err = Verify(doc, artifact, wrongMeasurement, nil, testShape, reportData)
	assert.Error(t, err)

	// An assembly without the required code expectation must reject.
	_, err = Assemble(artifact, nil, nil, testShape, reportData, q)
	assert.ErrorContains(t, err, "code measurement is required")

	// An assembly without the required VM shape must reject.
	_, err = Assemble(artifact, asCode(q.Measurement), nil, nil, reportData, q)
	assert.ErrorContains(t, err, "VM shape is required")

	// A machine absent from the artifact must reject.
	unendorsed := *artifact
	unendorsed.Machines = map[string]string{}
	_, _, err = Verify(doc, &unendorsed, asCode(q.Measurement), nil, testShape, reportData)
	assert.ErrorContains(t, err, "not endorsed")

	// v3 is single-request: a document without its endorsement collateral is
	// rejected, never patched up with a network fetch.
	noVCEK := *doc
	noVCEK.Collateral = nil
	_, _, err = Verify(&noVCEK, artifact, asCode(q.Measurement), nil, testShape, reportData)
	assert.ErrorContains(t, err, "no amd-vcek endorsement collateral")

	// A document without the CRL collateral must reject.
	noCRL := *doc
	noCRL.Collateral = doc.Collateral[:1]
	_, _, err = Verify(&noCRL, artifact, asCode(q.Measurement), nil, testShape, reportData)
	assert.ErrorContains(t, err, "no amd-crl endorsement collateral")
}

func TestVerifySEVRejectsBadCRL(t *testing.T) {
	doc, _ := loadSEVFixture(t)

	badCRL, err := json.Marshal(envelope.AMDCRLCollateral{
		CRLDERBase64: base64.StdEncoding.EncodeToString([]byte("not a crl")),
	})
	require.NoError(t, err)
	doc.Collateral[1].Data = badCRL
	_, err = Authenticate(doc)
	assert.Error(t, err)
}

func TestVerifyUnknownFormat(t *testing.T) {
	doc := &envelope.Document{
		CPUEvidence: envelope.CPUEvidence{Format: "https://tinfoil.sh/format/unknown/v1"},
	}
	_, _, err := Verify(doc, &policy.Artifact{}, &measurement.Measurement{}, nil, testShape, [64]byte{})
	assert.Error(t, err)
	assert.Contains(t, fmt.Sprint(err), "unsupported cpu_evidence format")
}

func TestLayoutRequiresCanonicalRegisterCount(t *testing.T) {
	register := strings.Repeat("ab", 48)
	sev := &Authenticated{platform: policy.PlatformSEVSNP, Measurement: &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{register}}}
	code := &measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{register}}
	_, err := layout(code, nil, sev)
	assert.ErrorContains(t, err, "code measurement is https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1 with 1 registers")
}

func TestPinnedLayoutUsesAuthenticatedPlatform(t *testing.T) {
	register := strings.Repeat("ab", 48)
	code := &measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{register, register, register}}
	q := &Authenticated{platform: policy.PlatformTDX}
	pins := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}
	got, err := layout(code, pins, q)
	require.NoError(t, err, "the caller-controlled measurement summary is not an input to policy")
	assert.Equal(t, []string{"", "", register, register, register}, got)
	pins.Type = measurement.SevGuestV2
	_, err = layout(code, pins, q)
	assert.ErrorContains(t, err, "pinned measurement")
}

// asCode extracts the release registers from a guest measurement.
func asCode(m *measurement.Measurement) *measurement.Measurement {
	if m.Type == measurement.TdxGuestV2 {
		return &measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{"", m.Registers[2], m.Registers[3]}}
	}
	return &measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{m.Registers[0], "", ""}}
}
