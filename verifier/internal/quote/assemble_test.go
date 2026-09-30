package quote

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

// boundDocument parses a minimal well-formed document whose CPU evidence is
// report, so Assemble's document checks can run without hardware evidence.
func boundDocument(t *testing.T, report []byte) *document.Document {
	t.Helper()
	nonce := make([]byte, document.NonceSize)
	cryptoBytes, err := json.Marshal(document.CryptoMaterialSection{Format: document.CryptoMaterialV1Format, Items: []document.CryptoMaterialItem{}})
	require.NoError(t, err)
	deviceBytes, err := json.Marshal(document.DeviceEvidenceSection{Format: document.DeviceEvidenceV1Format, Items: []document.DeviceEvidenceItem{}})
	require.NoError(t, err)
	cryptoHash := sha256.Sum256(cryptoBytes)
	deviceHash := sha256.Sum256(deviceBytes)
	reportData, err := document.ComputeReportData(nonce, cryptoHash[:], deviceHash[:])
	require.NoError(t, err)
	docBytes, err := json.Marshal(document.Document{
		Format: document.AttestationV3Format,
		Challenge: document.Challenge{
			Nonce:               hex.EncodeToString(nonce),
			ReportData:          hex.EncodeToString(reportData[:]),
			ReportDataAlgorithm: document.ReportDataV1Algorithm,
		},
		CPUEvidence: document.CPUEvidence{
			Format:       document.SEVSNPReportV1Format,
			ReportBase64: base64.StdEncoding.EncodeToString(report),
			Endorsed: document.EndorsedHashes{
				CryptoMaterialHash: hex.EncodeToString(cryptoHash[:]),
				DeviceEvidenceHash: hex.EncodeToString(deviceHash[:]),
			},
		},
		CryptoMaterial: base64.StdEncoding.EncodeToString(cryptoBytes),
		DeviceEvidence: base64.StdEncoding.EncodeToString(deviceBytes),
		Collateral:     []document.CollateralEntry{},
	})
	require.NoError(t, err)
	doc, err := document.Parse(docBytes, nonce)
	require.NoError(t, err)
	return doc
}

func TestAssembleRequiresParsedDocument(t *testing.T) {
	var config *errs.ConfigurationError
	for _, doc := range []*document.Document{nil, {}} {
		_, err := Assemble(doc, &policy.Artifact{}, &measurement.Measurement{}, nil, testShape, &Authenticated{})
		require.ErrorAs(t, err, &config)
		assert.ErrorContains(t, err, "checked by document.Parse")
	}
}

func TestAssembleRejectsQuoteFromAnotherDocument(t *testing.T) {
	doc := boundDocument(t, []byte("report a"))
	var config *errs.ConfigurationError

	_, err := Assemble(doc, &policy.Artifact{}, &measurement.Measurement{}, nil, testShape, &Authenticated{report: []byte("report b")})
	require.ErrorAs(t, err, &config)
	assert.ErrorContains(t, err, "not this document's CPU evidence")

	// The quote authenticated from this document's own evidence passes the
	// origin check and reaches the policy inputs.
	_, err = Assemble(doc, &policy.Artifact{}, &measurement.Measurement{}, nil, testShape, &Authenticated{report: []byte("report a")})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not this document's CPU evidence")
	assert.ErrorContains(t, err, "authenticated quote is required")
}
