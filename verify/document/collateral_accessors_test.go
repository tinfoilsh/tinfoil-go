package document

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// documentWithCollateral decodes entries as Parse does and returns a document
// carrying them, for CPU evidence of the given format.
func documentWithCollateral(t *testing.T, evidenceFormat string, entries []collateral.Entry) *Document {
	t.Helper()
	set, err := collateral.Decode(entries)
	require.NoError(t, err)
	return &Document{evidence: CPUEvidence{Format: evidenceFormat}, collateral: set}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func cpuEntry(id, format, data string) collateral.Entry {
	return collateral.Entry{ID: id, Role: collateral.RoleEndorsement, Format: format, Subjects: []string{collateral.SubjectCPU}, Data: []byte(data)}
}

// allPlatformEntries carries both platforms' CPU collateral.
func allPlatformEntries() []collateral.Entry {
	return []collateral.Entry{
		cpuEntry("vcek", collateral.AMDVCEKV1Format, `{"vcek_der_base64":"`+b64("vcek der")+`","cert_chain_pem":"chain"}`),
		cpuEntry("crl", collateral.AMDCRLV1Format, `{"crl_der_base64":"`+b64("crl der")+`"}`),
		cpuEntry("pcs", collateral.IntelPCSV1Format, `{"responses":[{"url":"https://pcs.example","headers":{},"body_base64":"`+b64("body")+`"}]}`),
	}
}

// Only the evidence's platform is returned.
func TestCPUEndorsementsSelectsEvidencePlatform(t *testing.T) {
	sev := documentWithCollateral(t, SEVSNPReportV1Format, allPlatformEntries()).CPUEndorsements()
	assert.Equal(t, collateral.CPUEndorsements{
		AMDVCEK: &collateral.AMDVCEK{VCEKDER: []byte("vcek der"), CertChainPEM: "chain"},
		AMDCRL:  &collateral.AMDCRL{CRLDER: []byte("crl der")},
	}, sev)

	tdx := documentWithCollateral(t, TDXQuoteV1Format, allPlatformEntries()).CPUEndorsements()
	assert.Equal(t, collateral.CPUEndorsements{IntelPCS: &collateral.IntelPCS{Responses: []collateral.PCSResponse{
		{URL: "https://pcs.example", Headers: map[string][]string{}, Body: []byte("body")},
	}}}, tdx)

	unknown := documentWithCollateral(t, "https://example.com/format/unknown", allPlatformEntries()).CPUEndorsements()
	assert.Equal(t, collateral.CPUEndorsements{}, unknown)
}

func TestCPUEndorsementsLeavesMissingCollateralNil(t *testing.T) {
	for _, format := range []string{SEVSNPReportV1Format, TDXQuoteV1Format} {
		en := documentWithCollateral(t, format, nil).CPUEndorsements()
		assert.Equal(t, collateral.CPUEndorsements{}, en, "absence is for Authenticate to reject")
	}
}

func TestCPUEndorsementsReturnsCopies(t *testing.T) {
	doc := documentWithCollateral(t, SEVSNPReportV1Format, allPlatformEntries())
	en := doc.CPUEndorsements()
	en.AMDVCEK.VCEKDER[0] = '!'
	en.AMDCRL = nil
	again := doc.CPUEndorsements()
	assert.Equal(t, []byte("vcek der"), again.AMDVCEK.VCEKDER)
	assert.NotNil(t, again.AMDCRL)
}

func TestReferenceValuesReturnCopies(t *testing.T) {
	doc := documentWithCollateral(t, "", []collateral.Entry{
		{ID: "code", Role: collateral.RoleReferenceValues, Format: collateral.SigstoreCodeV1Format, Data: []byte(`{"repo":"o/r","tag":"v1","digest":"ab","sigstore_bundle":{"a":1}}`)},
		{ID: collateral.FreshnessIDCode, Role: collateral.RoleReferenceValues, Format: collateral.SigstoreFreshnessV1Format, Data: []byte(`{"sigstore_bundle":{"b":2}}`)},
	})
	code, err := doc.SigstoreCode()
	require.NoError(t, err)
	code.Bundle[0] = '!'
	witness, err := doc.Freshness(collateral.FreshnessIDCode)
	require.NoError(t, err)
	witness.Bundle[0] = '!'

	code, err = doc.SigstoreCode()
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(code.Bundle))
	witness, err = doc.Freshness(collateral.FreshnessIDCode)
	require.NoError(t, err)
	assert.JSONEq(t, `{"b":2}`, string(witness.Bundle))
}

func TestContainerProvenanceIsKeyedByImageDigest(t *testing.T) {
	first, second := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	entry := func(id, data string) collateral.Entry {
		return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: collateral.ContainerProvenanceV1Format, Data: []byte(data)}
	}
	doc := documentWithCollateral(t, "", []collateral.Entry{
		entry("one", `{"digest":"`+first+`","sigstore_bundle":{"a":1}}`),
		entry("two", `{"digest":"`+second+`","sigstore_bundle":{"b":2}}`),
		entry("again", `{"digest":"`+first+`","sigstore_bundle":{"c":3}}`),
	})
	bundle, err := doc.ContainerProvenance(first)
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(bundle), "the first entry for a digest is the one used")
	bundle[0] = '!'
	bundle, err = doc.ContainerProvenance(first)
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(bundle))
	bundle, err = doc.ContainerProvenance(second)
	require.NoError(t, err)
	assert.JSONEq(t, `{"b":2}`, string(bundle))
	_, err = doc.ContainerProvenance(strings.Repeat("ef", 32))
	require.ErrorIs(t, err, collateral.ErrNotFound)

	for name, data := range map[string]string{
		"uppercase digest": `{"digest":"` + strings.ToUpper(first) + `","sigstore_bundle":{}}`,
		"prefixed digest":  `{"digest":"sha256:` + first + `","sigstore_bundle":{}}`,
		"missing bundle":   `{"digest":"` + first + `"}`,
		"unknown member":   `{"digest":"` + first + `","sigstore_bundle":{},"repo":"o/r"}`,
	} {
		_, err := collateral.Decode([]collateral.Entry{entry("one", data)})
		require.Error(t, err, name)
	}
}
