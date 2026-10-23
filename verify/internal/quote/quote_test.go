package quote

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
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
	q, err := Authenticate(evidence, endorsements, time.Now(), nil)
	require.NoError(t, err)
	assembled, verified, err := verify(evidence, endorsements, artifact, asCode(q.Measurement), nil, testShape, reportData, nil)
	require.NoError(t, err)
	assert.Equal(t, policy.PlatformSEVSNP, verified.Platform())
	assert.Equal(t, "amd-genoa-prod", assembled.PolicyName)
	assert.NotEmpty(t, verified.Identity())
	assert.IsType(t, measurement.SEVSNP{}, verified.Measurement)
	*verified = Authenticated{}
	require.NoError(t, assembled.Validate(), "assembly must retain its original authenticated quote")

	// Wrong REPORT_DATA must reject even with a valid signature.
	wrongReportData := reportData
	wrongReportData[0] ^= 0xff
	_, _, err = verify(evidence, endorsements, artifact, asCode(q.Measurement), nil, testShape, wrongReportData, nil)
	assert.ErrorContains(t, err, "REPORT_DATA")

	// A launch measurement differing from the code expectation must reject.
	wrongMeasurement := asCode(q.Measurement)
	wrongMeasurement.SEVSNP.Launch = &measurement.Register{0xab}
	_, _, err = verify(evidence, endorsements, artifact, wrongMeasurement, nil, testShape, reportData, nil)
	assert.Error(t, err)

	// SEV assembly does not consume the code artifact's VM shape.
	code := asCode(q.Measurement)
	code.Endorsements = artifact
	_, err = assemble(code, nil, reportData, q)
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
	_, err = Authenticate(evidence, endorsements, time.Now(), nil)
	assert.ErrorContains(t, err, "parsing amd-crl collateral")
}

func TestVerifyUnknownFormat(t *testing.T) {
	evidence := document.CPUEvidence{Format: "https://tinfoil.sh/format/unknown/v1"}
	_, _, err := verify(evidence, collateral.CPUEndorsements{}, &policy.Artifact{}, LegacyReferenceValues{}, nil, testShape, [64]byte{}, nil)
	assert.Error(t, err)
	assert.Contains(t, fmt.Sprint(err), "unsupported cpu_evidence format")
}

func TestPinsUseAuthenticatedPlatform(t *testing.T) {
	register := measurement.Register{0xab}
	r := register.String()
	tdxRelease := func() []string { return registersOf(measurement.ExpectedTDX{RTMR1: &register, RTMR2: &register}) }
	sevRelease := func() []string { return registersOf(measurement.ExpectedSEVSNP{Launch: &register}) }
	got, err := applyPins(tdxRelease(), policy.PlatformTDX, measurement.ExpectedTDX{RTMR3: &register})
	require.NoError(t, err)
	assert.Equal(t, []string{"", "", r, r, r}, got, "a pin fills a register the release leaves open")
	got, err = applyPins(sevRelease(), policy.PlatformSEVSNP, measurement.ExpectedSEVSNP{Launch: &register})
	require.NoError(t, err)
	assert.Equal(t, []string{r}, got, "a pin may repeat a register the release fixes")
	_, err = applyPins(tdxRelease(), policy.PlatformTDX, &measurement.ExpectedTDX{})
	assert.ErrorContains(t, err, "unsupported pinned measurement", "NewVerifier stores pins as values; anything else fails closed")

	// Pins for the other platform reject in both directions, even when their
	// value equals a register the release fixes.
	_, err = applyPins(tdxRelease(), policy.PlatformTDX, measurement.ExpectedSEVSNP{Launch: &register})
	assert.ErrorContains(t, err, "pinned registers are for sev-snp, but the enclave is tdx")
	_, err = applyPins(sevRelease(), policy.PlatformSEVSNP, measurement.ExpectedTDX{RTMR1: &register})
	assert.ErrorContains(t, err, "pinned registers are for tdx, but the enclave is sev-snp")
}

// asCode returns the registers a release fixes for the measured guest: the
// SEV-SNP launch measurement, or TDX RTMR1 and RTMR2.
func asCode(m measurement.Measurement) LegacyReferenceValues {
	switch m := m.(type) {
	case measurement.SEVSNP:
		return LegacyReferenceValues{SEVSNP: measurement.ExpectedSEVSNP{Launch: &m.Launch}}
	case measurement.TDX:
		return LegacyReferenceValues{TDX: measurement.ExpectedTDX{RTMR1: &m.RTMR1, RTMR2: &m.RTMR2}}
	default:
		return LegacyReferenceValues{}
	}
}

// verify composes Authenticate, assemble against an explicit REPORT_DATA, and
// Validate at the current time, for tests whose evidence predates the v3
// REPORT_DATA ladder. A nil opts selects the embedded vendor roots.
func verify(ev document.CPUEvidence, en collateral.CPUEndorsements, endorsements *policy.Artifact, code LegacyReferenceValues, pins measurement.Expected, shape *policy.Shape, reportData [64]byte, opts *Options) (*AssembledPolicy, *Authenticated, error) {
	q, err := Authenticate(ev, en, time.Now(), opts)
	if err != nil {
		return nil, nil, err
	}
	code.Endorsements, code.Shape = endorsements, shape
	assembled, err := assemble(code, pins, reportData, q)
	if err != nil {
		return nil, nil, err
	}
	if err := assembled.Validate(); err != nil {
		return nil, nil, err
	}
	return assembled, q, nil
}
