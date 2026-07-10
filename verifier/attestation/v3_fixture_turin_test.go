package attestation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// TestVerifyV3LiveFixtureTurin checks the fail-closed behavior for AMD Turin
// (family 1Ah) hardware, which the verifier does not support yet: the
// envelope of a real Turin-served document verifies (nonce, section hashes,
// REPORT_DATA ladder), but CPU evidence verification must reject rather than
// partially apply. Skips when the fixture is absent.
func TestVerifyV3LiveFixtureTurin(t *testing.T) {
	root := filepath.Join("..", "..", "..", "attestation-samples", "box2-turin-v3")
	docBytes, err := os.ReadFile(filepath.Join(root, "fresh-v3.json"))
	if os.IsNotExist(err) {
		t.Skip("live Turin v3 fixture not collected")
	}
	require.NoError(t, err)

	metaBytes, err := os.ReadFile(filepath.Join(root, "metadata.json"))
	require.NoError(t, err)
	var meta struct {
		Nonce string `json:"nonce"`
	}
	require.NoError(t, json.Unmarshal(metaBytes, &meta))
	nonce, err := hex.DecodeString(meta.Nonce)
	require.NoError(t, err)

	doc, reportData, err := VerifyEnvelopeV3(docBytes, nonce)
	require.NoError(t, err)
	require.Equal(t, SEVSNPReportV1Format, doc.CPUEvidence.Format)

	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.ParseArtifact(artifactBytes)
	require.NoError(t, err)

	// Turin quotes must fail verification, never partially verify.
	_, err = VerifyCPUEvidenceV3(doc, reportData, artifact)
	assert.Error(t, err)
}
