package quote

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

func TestEvidenceFromDocumentDecodesReport(t *testing.T) {
	for _, format := range []string{document.SEVSNPReportV1Format, document.TDXQuoteV1Format} {
		report := []byte("report for " + format)
		doc := &document.Document{CPUEvidence: document.CPUEvidence{Format: format, ReportBase64: base64.StdEncoding.EncodeToString(report)}}
		ev, err := EvidenceFromDocument(doc)
		require.NoError(t, err)
		assert.Equal(t, CPUEvidence{Format: format, Report: report}, ev)
	}
}
