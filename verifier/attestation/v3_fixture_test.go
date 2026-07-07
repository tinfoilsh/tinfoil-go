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

// TestVerifyV3LiveFixture runs envelope and CPU-evidence verification against
// a v3 document captured from real SEV-SNP Genoa hardware over the
// single-request flow (evidence + collateral in one response). Everything
// here is offline: the VCEK comes from the document's own collateral and the
// endorsement artifact from the policy package's testdata. Skips when the
// workspace fixture directory is not present.
func TestVerifyV3LiveFixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "attestation-samples", "box3-genoa-v3")
	docBytes, err := os.ReadFile(filepath.Join(root, "fresh-v3.json"))
	if os.IsNotExist(err) {
		t.Skip("live v3 fixture not collected")
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

	// The endorsed key material must be present and well-formed.
	tls, ok := doc.CryptoMaterialItem(CryptoMaterialIDTLS)
	require.True(t, ok)
	assert.Equal(t, KeySPKIFPSHA256V1Format, tls.Format)
	hpke, ok := doc.CryptoMaterialItem(CryptoMaterialIDHPKE)
	require.True(t, ok)
	assert.Equal(t, KeyX25519HPKEV1Format, hpke.Format)

	// Both reference-values entries travel in the document.
	codeRef, found, err := doc.ReferenceValuesCollateral(CollateralSigstoreCodeV1Format)
	require.NoError(t, err)
	require.True(t, found)
	assert.NotEmpty(t, codeRef.Digest)
	platformRef, found, err := doc.ReferenceValuesCollateral(CollateralSigstorePlatformV1Format)
	require.NoError(t, err)
	require.True(t, found)
	assert.NotEmpty(t, platformRef.Digest)

	artifactBytes, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "platform-endorsements.json"))
	require.NoError(t, err)
	artifact, err := policy.ParseArtifact(artifactBytes)
	require.NoError(t, err)

	evidence, err := VerifyCPUEvidenceV3(doc, reportData, artifact)
	require.NoError(t, err)
	assert.Equal(t, policy.PlatformSEVSNP, evidence.Platform)
	assert.Equal(t, "amd-genoa-prod", evidence.PolicyName)

	// A wrong nonce must reject at the envelope.
	wrongNonce := append([]byte(nil), nonce...)
	wrongNonce[0] ^= 0xff
	_, _, err = VerifyEnvelopeV3(docBytes, wrongNonce)
	assert.ErrorContains(t, err, "nonce")
}
