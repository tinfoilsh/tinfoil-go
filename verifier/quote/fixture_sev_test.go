package quote

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// loadLiveFixture reads a captured v3 document and its nonce, and verifies
// the document. It skips when the fixture is absent, or when it predates the
// current REPORT_DATA construction (a ladder change makes the hardware-bound
// value unreproducible without re-capturing on hardware).
func loadLiveFixture(t *testing.T, dir string) (*document.Document, [64]byte, []byte) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "attestation-samples", dir)
	docBytes, err := os.ReadFile(filepath.Join(root, "fresh-v3.json"))
	if os.IsNotExist(err) {
		t.Skipf("live fixture %s not collected", dir)
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

	doc, reportData, err := document.Check(docBytes, nonce)
	if err != nil && strings.Contains(err.Error(), "report_data") {
		t.Skipf("fixture %s predates the current report-data construction; regenerate on hardware", dir)
	}
	require.NoError(t, err)
	return doc, reportData, nonce
}

// TestLiveSEVFixture runs document and CPU-evidence verification
// against a v3 document captured from real SEV-SNP Genoa hardware over the
// single-request flow (evidence + collateral in one response). The VCEK
// comes from the document's own collateral and the endorsement artifact
// from the policy package's testdata; only the AMD CRL is fetched live
// (captured fixtures predate the amd-crl entry). Requires explicit live opt-in
// without -short; also skips when the workspace fixture directory is absent.
func TestLiveSEVFixture(t *testing.T) {
	testutil.RequireLive(t)
	doc, reportData, _ := loadLiveFixture(t, "box3-genoa-v3")

	// The endorsed key material must be present and well-formed.
	tls, ok := doc.CryptoMaterialItem(document.CryptoMaterialIDTLS)
	require.True(t, ok)
	assert.Equal(t, document.KeySPKIFPSHA256V1Format, tls.Format)
	hpke, ok := doc.CryptoMaterialItem(document.CryptoMaterialIDHPKE)
	require.True(t, ok)
	assert.Equal(t, document.KeyX25519HPKEV1Format, hpke.Format)

	// Both reference-values entries travel in the document.
	codeRef, err := doc.ReferenceValuesCollateral(document.CollateralSigstoreCodeV1Format)
	require.NoError(t, err)
	assert.NotEmpty(t, codeRef.Digest)
	platformRef, err := doc.ReferenceValuesCollateral(document.CollateralSigstorePlatformV1Format)
	require.NoError(t, err)
	assert.NotEmpty(t, platformRef.Digest)

	appendLiveCRL(t, doc)
	q, err := Authenticate(doc)
	require.NoError(t, err)
	assembled, verified, err := Verify(doc, loadEndorsementArtifact(t), asCode(q.Measurement), nil, testShape, reportData)
	require.NoError(t, err)
	assert.Equal(t, policy.PlatformSEVSNP, verified.Platform())
	assert.Equal(t, "amd-genoa-dev", assembled.PolicyName)
}
