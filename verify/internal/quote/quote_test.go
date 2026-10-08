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
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// testShape is an arbitrary required shape for paths that do not consume it
// (SEV assembly).
var testShape = &policy.Shape{CPUs: 1, MemoryMB: 1, Disks: 1}

// loadSEVFixture builds CPU evidence from a live-captured production Genoa
// report, its VCEK collateral, and a live-fetched AMD CRL (captured
// documents predate the amd-crl entry). The captured report predates the v3
// REPORT_DATA ladder, so the expected REPORT_DATA is taken from the report
// itself; the document ladder is covered by the document package tests.
// Skips when the workspace fixture directory is not present.
func loadSEVFixture(t *testing.T) (document.CPUEvidence, collateral.CPUEndorsements, [64]byte) {
	t.Helper()
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

	vcekDER, err := base64.StdEncoding.DecodeString(material.Collateral.CPUVendor.SEVSNP.VCEKDERBase64)
	require.NoError(t, err)
	evidence := document.CPUEvidence{Format: document.SEVSNPReportV1Format, Report: reportBytes}
	endorsements := collateral.CPUEndorsements{
		AMDVCEK: &collateral.AMDVCEK{VCEKDER: vcekDER, CertChainPEM: material.Collateral.CPUVendor.SEVSNP.CertChainPEM},
		AMDCRL:  liveCRL(t),
	}
	return evidence, endorsements, reportData
}

// liveCRL fetches the Genoa amd-crl collateral exactly as the builder does.
func liveCRL(t *testing.T) *collateral.AMDCRL {
	t.Helper()
	crlBytes, err := testutil.Get("https://kdsintf.amd.com/vcek/v1/Genoa/crl")
	require.NoError(t, err)
	return &collateral.AMDCRL{CRLDER: crlBytes}
}

func loadEndorsementArtifact(t *testing.T) *policy.Artifact {
	t.Helper()
	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.Parse(artifactBytes)
	require.NoError(t, err)
	return artifact
}

func TestLiveVerifySEV(t *testing.T) {
	testutil.RequireLive(t)
	evidence, endorsements, reportData := loadSEVFixture(t)
	artifact := loadEndorsementArtifact(t)

	// The fixture predates per-release code provenance, so the expected
	// launch measurement is the quote's own; the equality path is still
	// exercised, and the mismatch case is covered below.
	q, err := Authenticate(evidence, endorsements, nil)
	require.NoError(t, err)
	assembled, verified, err := verify(evidence, endorsements, artifact, asCode(q.Measurement), nil, testShape, reportData, nil)
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
	_, _, err = verify(evidence, endorsements, artifact, asCode(q.Measurement), nil, testShape, wrongReportData, nil)
	assert.ErrorContains(t, err, "REPORT_DATA")

	// A launch measurement differing from the code expectation must reject.
	wrongMeasurement := asCode(q.Measurement)
	wrongMeasurement.Registers[0] = strings.Repeat("ab", 48)
	_, _, err = verify(evidence, endorsements, artifact, wrongMeasurement, nil, testShape, reportData, nil)
	assert.Error(t, err)

	// An assembly without the required code expectation must reject.
	_, err = assemble(LegacyReferenceValues{Endorsements: artifact, Shape: testShape}, nil, reportData, q)
	assert.ErrorContains(t, err, "code measurement is required")

	// SEV assembly does not consume the code artifact's VM shape.
	_, err = assemble(LegacyReferenceValues{Endorsements: artifact, Code: asCode(q.Measurement)}, nil, reportData, q)
	require.NoError(t, err)

	// A machine absent from the artifact must reject.
	unendorsed := *artifact
	unendorsed.Machines = map[string]string{}
	_, _, err = verify(evidence, endorsements, &unendorsed, asCode(q.Measurement), nil, testShape, reportData, nil)
	assert.ErrorContains(t, err, "not endorsed")

	// v3 is single-request: evidence without its endorsement collateral is
	// rejected, never patched up with a network fetch.
	noVCEK := endorsements
	noVCEK.AMDVCEK = nil
	_, _, err = verify(evidence, noVCEK, artifact, asCode(q.Measurement), nil, testShape, reportData, nil)
	assert.ErrorContains(t, err, "no amd-vcek endorsement collateral")

	// Evidence without the CRL collateral must reject.
	noCRL := endorsements
	noCRL.AMDCRL = nil
	_, _, err = verify(evidence, noCRL, artifact, asCode(q.Measurement), nil, testShape, reportData, nil)
	assert.ErrorContains(t, err, "no amd-crl endorsement collateral")
}

func TestVerifySEVRejectsBadCRL(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("sev", "testdata", "inf17.json"))
	require.NoError(t, err)
	var fixture struct {
		Report string `json:"report_base64"`
		VCEK   string `json:"vcek_der_base64"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))
	chain, err := os.ReadFile(filepath.Join("sev", "turin_cert_chain.pem"))
	require.NoError(t, err)
	report, err := base64.StdEncoding.DecodeString(fixture.Report)
	require.NoError(t, err)
	vcekDER, err := base64.StdEncoding.DecodeString(fixture.VCEK)
	require.NoError(t, err)
	evidence := document.CPUEvidence{Format: document.SEVSNPReportV1Format, Report: report}
	endorsements := collateral.CPUEndorsements{
		AMDVCEK: &collateral.AMDVCEK{VCEKDER: vcekDER, CertChainPEM: string(chain)},
		AMDCRL:  &collateral.AMDCRL{CRLDER: []byte("not a crl")},
	}
	_, err = Authenticate(evidence, endorsements, nil)
	assert.ErrorContains(t, err, "parsing amd-crl collateral")
}

func TestVerifyUnknownFormat(t *testing.T) {
	evidence := document.CPUEvidence{Format: "https://tinfoil.sh/format/unknown/v1"}
	_, _, err := verify(evidence, collateral.CPUEndorsements{}, &policy.Artifact{}, &measurement.Measurement{}, nil, testShape, [64]byte{}, nil)
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
	pins.Registers = []string{register}
	_, err = layout(code, pins, q)
	assert.ErrorContains(t, err, "pinned measurement")
	for _, malformed := range []*measurement.Measurement{
		{Type: "unknown"},
		{Type: measurement.SevGuestV2, Registers: []string{}},
		{Type: measurement.TdxGuestV2, Registers: []string{4: "bad"}},
	} {
		_, err = layout(code, malformed, q)
		var config *errs.ConfigurationError
		require.ErrorAs(t, err, &config, "phase callers receive the same pin validation as client options")
	}
}

func TestMissingTDXShapePrecedesPolicyLookup(t *testing.T) {
	q := &Authenticated{platform: policy.PlatformTDX, tdx: &tdx.Quote{}}
	_, err := assemble(LegacyReferenceValues{Endorsements: &policy.Artifact{}, Code: &measurement.Measurement{}}, nil, [64]byte{}, q)
	var config *errs.ConfigurationError
	require.ErrorAs(t, err, &config)
	require.ErrorContains(t, err, "VM shape", "missing input must be reported before the unendorsed machine")
}

// asCode extracts the release registers from a guest measurement.
func asCode(m *measurement.Measurement) *measurement.Measurement {
	if m.Type == measurement.TdxGuestV2 {
		return &measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{"", m.Registers[2], m.Registers[3]}}
	}
	return &measurement.Measurement{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{m.Registers[0], "", ""}}
}

// verify composes Authenticate, assemble against an explicit REPORT_DATA, and
// Validate, for tests whose evidence predates the v3 REPORT_DATA ladder. A nil
// opts selects the production clock and embedded vendor roots.
func verify(ev document.CPUEvidence, en collateral.CPUEndorsements, endorsements *policy.Artifact, code, pins *measurement.Measurement, shape *policy.Shape, reportData [64]byte, opts *Options) (*AssembledPolicy, *Authenticated, error) {
	q, err := Authenticate(ev, en, opts)
	if err != nil {
		return nil, nil, err
	}
	assembled, err := assemble(LegacyReferenceValues{Endorsements: endorsements, Code: code, Shape: shape}, pins, reportData, q)
	if err != nil {
		return nil, nil, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, nil, err
	}
	return assembled, q, nil
}
