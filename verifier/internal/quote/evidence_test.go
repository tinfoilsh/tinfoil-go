package quote

import (
	"encoding/base64"
	"encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

func collateralEntry(t *testing.T, id, format string, payload any) document.CollateralEntry {
	t.Helper()
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	return document.CollateralEntry{ID: id, Role: document.RoleEndorsement, Format: format, Subjects: []string{document.SubjectCPU}, Data: data}
}

func TestEvidenceFromDocumentDecodesSEVCollateral(t *testing.T) {
	report := []byte("report")
	doc := &document.Document{
		CPUEvidence: document.CPUEvidence{Format: document.SEVSNPReportV1Format, ReportBase64: base64.StdEncoding.EncodeToString(report)},
		Collateral: []document.CollateralEntry{
			collateralEntry(t, "cpu-endorsement", document.CollateralAMDVCEKV1Format, document.AMDVCEKCollateral{VCEKDERBase64: base64.StdEncoding.EncodeToString([]byte("vcek der")), CertChainPEM: "chain"}),
			collateralEntry(t, "cpu-crl", document.CollateralAMDCRLV1Format, document.AMDCRLCollateral{CRLDERBase64: base64.StdEncoding.EncodeToString([]byte("crl der"))}),
		},
	}
	ev, en, err := EvidenceFromDocument(doc)
	require.NoError(t, err)
	assert.Equal(t, CPUEvidence{Format: document.SEVSNPReportV1Format, Report: report}, ev)
	assert.Equal(t, &AMDVCEK{VCEKDER: []byte("vcek der"), CertChainPEM: "chain"}, en.AMDVCEK)
	assert.Equal(t, &AMDCRL{CRLDER: []byte("crl der")}, en.AMDCRL)
	assert.Nil(t, en.IntelPCS)
}

func TestEvidenceFromDocumentLeavesMissingCollateralNil(t *testing.T) {
	for _, format := range []string{document.SEVSNPReportV1Format, document.TDXQuoteV1Format} {
		doc := &document.Document{CPUEvidence: document.CPUEvidence{Format: format}}
		_, en, err := EvidenceFromDocument(doc)
		require.NoError(t, err, "absence is for Authenticate to reject")
		assert.Equal(t, CPUEndorsements{}, en)
	}
}

func TestEvidenceFromDocumentIgnoresOtherPlatformCollateral(t *testing.T) {
	// A malformed entry for the other platform is never decoded.
	malformed := document.CollateralEntry{ID: "vcek", Role: document.RoleEndorsement, Format: document.CollateralAMDVCEKV1Format, Subjects: []string{document.SubjectCPU}, Data: []byte(`{"unknown":1}`)}
	doc := &document.Document{
		CPUEvidence: document.CPUEvidence{Format: document.TDXQuoteV1Format},
		Collateral:  []document.CollateralEntry{malformed},
	}
	_, en, err := EvidenceFromDocument(doc)
	require.NoError(t, err)
	assert.Nil(t, en.AMDVCEK)
}

func TestEvidenceFromDocumentRejectsNonCanonicalCollateralBase64(t *testing.T) {
	vcek := base64.StdEncoding.EncodeToString([]byte("vcek der"))
	crl := base64.StdEncoding.EncodeToString([]byte("crl der"))

	tests := []struct {
		name    string
		vcek    string
		crl     string
		wantErr string
	}{
		{name: "vcek", vcek: vcek + "\n", crl: crl, wantErr: `amd-vcek collateral entry "cpu-endorsement": vcek_der_base64 is not canonical base64`},
		{name: "crl", vcek: vcek, crl: crl + "\n", wantErr: `amd-crl collateral entry "cpu-crl": crl_der_base64 is not canonical base64`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &document.Document{
				CPUEvidence: document.CPUEvidence{Format: document.SEVSNPReportV1Format},
				Collateral: []document.CollateralEntry{
					collateralEntry(t, "cpu-endorsement", document.CollateralAMDVCEKV1Format, document.AMDVCEKCollateral{VCEKDERBase64: tt.vcek, CertChainPEM: "chain"}),
					collateralEntry(t, "cpu-crl", document.CollateralAMDCRLV1Format, document.AMDCRLCollateral{CRLDERBase64: tt.crl}),
				},
			}
			_, _, err := EvidenceFromDocument(doc)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
