package attestation

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// TestVerifyV3LiveFixtureTDX runs envelope and TDX CPU-evidence verification
// against a v3 document captured from real TDX hardware over the
// single-request flow. Quote verification replays the document's own
// captured Intel PCS collateral — fully offline.
//
// The captured enclave ran a dev VM shape, so the policy's
// platform_measurements check correctly rejects it; the test first proves
// that rejection, then injects the observed MRTD/RTMR0 as an extra allowed
// configuration to exercise the rest of the chain (quote signature,
// collateral replay, TCB evaluation floor, MR_SEAM, PPID identity, policy).
// Skips when the fixture is absent or its captured collateral has expired.
func TestVerifyV3LiveFixtureTDX(t *testing.T) {
	root := filepath.Join("..", "..", "..", "attestation-samples", "inf14-tdx-v3")
	docBytes, err := os.ReadFile(filepath.Join(root, "fresh-v3.json"))
	if os.IsNotExist(err) {
		t.Skip("live TDX v3 fixture not collected")
	}
	require.NoError(t, err)

	metaBytes, err := os.ReadFile(filepath.Join(root, "metadata.json"))
	require.NoError(t, err)
	var meta struct {
		Nonce  string `json:"nonce"`
		Policy string `json:"policy"`
	}
	require.NoError(t, json.Unmarshal(metaBytes, &meta))
	nonce, err := hex.DecodeString(meta.Nonce)
	require.NoError(t, err)

	doc, reportData, err := VerifyEnvelopeV3(docBytes, nonce)
	require.NoError(t, err)
	require.Equal(t, TDXQuoteV1Format, doc.CPUEvidence.Format)

	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.ParseArtifact(artifactBytes)
	require.NoError(t, err)

	// The dev shape must be rejected by the endorsed platform measurements.
	_, err = VerifyCPUEvidenceV3(doc, reportData, artifact)
	if err != nil && strings.Contains(err.Error(), "expired") {
		t.Skipf("captured Intel PCS collateral has expired: %v", err)
	}
	require.Error(t, err)
	assert.ErrorContains(t, err, "platform measurements")

	// Allow the observed shape and verify the rest of the chain.
	require.NoError(t, allowObservedShape(doc, artifact))
	evidence, err := VerifyCPUEvidenceV3(doc, reportData, artifact)
	require.NoError(t, err)
	assert.Equal(t, policy.PlatformTDX, evidence.Platform)
	assert.Equal(t, meta.Policy, evidence.PolicyName)
	require.NotNil(t, evidence.Measurement)
	assert.Equal(t, TdxGuestV2, evidence.Measurement.Type)
	assert.Len(t, evidence.Measurement.Registers, 5)
}

// allowObservedShape adds the quote's own MRTD/RTMR0 to every TDX policy as
// an allowed platform configuration (test only).
func allowObservedShape(doc *DocumentV3, artifact *policy.Artifact) error {
	raw, err := base64.StdEncoding.DecodeString(doc.CPUEvidence.ReportBase64)
	if err != nil {
		return err
	}
	parsed, err := tdxabi.QuoteToProto(raw)
	if err != nil {
		return err
	}
	quote, ok := parsed.(*tdxpb.QuoteV4)
	if !ok {
		return fmt.Errorf("unsupported TDX quote version (want v4)")
	}
	body := quote.GetTdQuoteBody()
	artifact.Measurements["dev-shape"] = policy.PlatformMeasurement{
		MRTD:  hex.EncodeToString(body.GetMrTd()),
		RTMR0: hex.EncodeToString(body.GetRtmrs()[0]),
	}
	for name, p := range artifact.Policies {
		if p.TDX != nil {
			p.TDX.PlatformMeasurements = append(p.TDX.PlatformMeasurements, "dev-shape")
			artifact.Policies[name] = p
		}
	}
	return nil
}
