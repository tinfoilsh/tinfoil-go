package attestation

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	sevtestdata "github.com/tinfoilsh/go-sev-guest/verify/testdata"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

func TestVerifyTurinAttestationV2(t *testing.T) {
	reportRaw, err := sevtestdata.Box2TurinReport()
	require.NoError(t, err)
	vcek, err := sevtestdata.Box2TurinVcek()
	require.NoError(t, err)
	report, err := sevabi.ReportToProto(reportRaw)
	require.NoError(t, err)

	document, err := NewDocument(SevGuestV2, reportRaw)
	require.NoError(t, err)
	verification, err := document.VerifyWithVCEK(vcek)
	require.NoError(t, err)
	assert.Equal(t, SevGuestV2, verification.Measurement.Type)
	assert.Equal(t, []string{hex.EncodeToString(report.GetMeasurement())}, verification.Measurement.Registers)
	assert.Equal(t, hex.EncodeToString(report.GetReportData()[:32]), verification.TLSPublicKeyFP)
	assert.Equal(t, hex.EncodeToString(report.GetReportData()[32:]), verification.HPKEPublicKey)
}

func TestVerifyTurinReportWithEndorsements(t *testing.T) {
	reportRaw, err := sevtestdata.Box2TurinReport()
	require.NoError(t, err)
	vcek, err := sevtestdata.Box2TurinVcek()
	require.NoError(t, err)
	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.ParseArtifact(artifactBytes)
	require.NoError(t, err)

	report, policyName, err := verifySevReportWithEndorsements(
		base64.StdEncoding.EncodeToString(reportRaw), false, vcek, artifact)
	require.NoError(t, err)
	assert.Equal(t, "amd-turin-prod", policyName)
	assert.Equal(t, box2TurinID, hex.EncodeToString(report.GetChipId()))
}

const box2TurinID = "6bb1229b7692b7100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
