package quote

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// boundDocument parses a minimal well-formed document whose CPU evidence is
// report, so Assemble's document checks can run without hardware evidence.
func boundDocument(t *testing.T, report []byte) *document.Document {
	t.Helper()
	nonce := make([]byte, document.NonceSize)
	docBytes, err := document.Build(document.BuildInput{Nonce: nonce}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, report, nil
	})
	require.NoError(t, err)
	doc, err := document.Parse(docBytes, nonce)
	require.NoError(t, err)
	return doc
}

func TestAssembleRequiresParsedDocument(t *testing.T) {
	for _, doc := range []*document.Document{nil, {}} {
		_, err := Assemble(doc, LegacyReferenceValues{Endorsements: &policy.Artifact{}, Code: &measurement.Measurement{}, Shape: testShape}, nil, &Authenticated{})
		require.Error(t, err)
		assert.ErrorContains(t, err, "checked by document.Parse")
	}
}

func TestAssembleRejectsQuoteFromAnotherDocument(t *testing.T) {
	doc := boundDocument(t, []byte("report a"))
	authenticated := func(format, report string) *Authenticated {
		return &Authenticated{evidence: document.CPUEvidence{Format: format, Report: []byte(report)}}
	}
	for name, q := range map[string]*Authenticated{
		"other report": authenticated(document.SEVSNPReportV1Format, "report b"),
		"other format": authenticated(document.TDXQuoteV1Format, "report a"),
	} {
		_, err := Assemble(doc, LegacyReferenceValues{Endorsements: &policy.Artifact{}, Code: &measurement.Measurement{}, Shape: testShape}, nil, q)
		require.Error(t, err, name)
		assert.ErrorContains(t, err, "not this document's CPU evidence", name)
	}

	// The quote authenticated from this document's own evidence passes the
	// origin check and reaches the policy inputs.
	_, err := Assemble(doc, LegacyReferenceValues{Endorsements: &policy.Artifact{}, Code: &measurement.Measurement{}, Shape: testShape}, nil, authenticated(document.SEVSNPReportV1Format, "report a"))
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not this document's CPU evidence")
	assert.ErrorContains(t, err, "is not endorsed")
}
