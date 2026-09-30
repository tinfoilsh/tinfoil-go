package document

import (
	"encoding/base64"
	"encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCollateralEntry(t *testing.T, id, format string, payload any) CollateralEntry {
	t.Helper()
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	return CollateralEntry{ID: id, Role: RoleEndorsement, Format: format, Subjects: []string{SubjectCPU}, Data: data}
}

func TestCPUEndorsementsDecodesSEVCollateral(t *testing.T) {
	report := []byte("report")
	doc := &Document{
		CPUEvidence: CPUEvidence{Format: SEVSNPReportV1Format, ReportBase64: base64.StdEncoding.EncodeToString(report)},
		Collateral: []CollateralEntry{
			testCollateralEntry(t, "cpu-endorsement", CollateralAMDVCEKV1Format, AMDVCEKCollateral{VCEKDERBase64: base64.StdEncoding.EncodeToString([]byte("vcek der")), CertChainPEM: "chain"}),
			testCollateralEntry(t, "cpu-crl", CollateralAMDCRLV1Format, AMDCRLCollateral{CRLDERBase64: base64.StdEncoding.EncodeToString([]byte("crl der"))}),
		},
	}
	en, err := doc.CPUEndorsements()
	require.NoError(t, err)
	assert.Equal(t, &AMDVCEK{VCEKDER: []byte("vcek der"), CertChainPEM: "chain"}, en.AMDVCEK)
	assert.Equal(t, &AMDCRL{CRLDER: []byte("crl der")}, en.AMDCRL)
	assert.Nil(t, en.IntelPCS)
}

func TestCPUEndorsementsDecodesTDXCollateral(t *testing.T) {
	quote := []byte("quote")
	pcs := IntelPCSCollateral{Responses: []PCSResponse{{
		URL:        "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
		Headers:    map[string][]string{"Sgx-Enclave-Identity-Issuer-Chain": {"chain"}},
		BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{"enclaveIdentity":{}}`)),
	}}}
	doc := &Document{
		CPUEvidence: CPUEvidence{Format: TDXQuoteV1Format, ReportBase64: base64.StdEncoding.EncodeToString(quote)},
		Collateral:  []CollateralEntry{testCollateralEntry(t, "pcs", CollateralIntelPCSV1Format, pcs)},
	}
	en, err := doc.CPUEndorsements()
	require.NoError(t, err)
	assert.Equal(t, &pcs, en.IntelPCS)
	assert.Nil(t, en.AMDVCEK)
	assert.Nil(t, en.AMDCRL)
}

func TestCPUEndorsementsRejectsMalformedIntelPCS(t *testing.T) {
	malformed := CollateralEntry{ID: "pcs", Role: RoleEndorsement, Format: CollateralIntelPCSV1Format, Subjects: []string{SubjectCPU}, Data: []byte(`{"unknown":1}`)}
	doc := &Document{
		CPUEvidence: CPUEvidence{Format: TDXQuoteV1Format},
		Collateral:  []CollateralEntry{malformed},
	}
	_, err := doc.CPUEndorsements()
	assert.ErrorContains(t, err, `parsing intel-pcs collateral entry "pcs"`)
}

func TestCPUEndorsementsLeavesMissingCollateralNil(t *testing.T) {
	for _, format := range []string{SEVSNPReportV1Format, TDXQuoteV1Format} {
		doc := &Document{CPUEvidence: CPUEvidence{Format: format}}
		en, err := doc.CPUEndorsements()
		require.NoError(t, err, "absence is for Authenticate to reject")
		assert.Equal(t, CPUEndorsements{}, en)
	}
}

func TestCPUEndorsementsIgnoresOtherPlatformCollateral(t *testing.T) {
	// A malformed entry for the other platform is never decoded.
	malformed := CollateralEntry{ID: "vcek", Role: RoleEndorsement, Format: CollateralAMDVCEKV1Format, Subjects: []string{SubjectCPU}, Data: []byte(`{"unknown":1}`)}
	doc := &Document{
		CPUEvidence: CPUEvidence{Format: TDXQuoteV1Format},
		Collateral:  []CollateralEntry{malformed},
	}
	en, err := doc.CPUEndorsements()
	require.NoError(t, err)
	assert.Nil(t, en.AMDVCEK)
}

func TestCPUEndorsementsRejectsNonCanonicalCollateralBase64(t *testing.T) {
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
			doc := &Document{
				CPUEvidence: CPUEvidence{Format: SEVSNPReportV1Format},
				Collateral: []CollateralEntry{
					testCollateralEntry(t, "cpu-endorsement", CollateralAMDVCEKV1Format, AMDVCEKCollateral{VCEKDERBase64: tt.vcek, CertChainPEM: "chain"}),
					testCollateralEntry(t, "cpu-crl", CollateralAMDCRLV1Format, AMDCRLCollateral{CRLDERBase64: tt.crl}),
				},
			}
			_, err := doc.CPUEndorsements()
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
