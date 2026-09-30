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
	doc := &Document{
		evidence: CPUEvidence{Format: SEVSNPReportV1Format},
		collateral: []CollateralEntry{
			testCollateralEntry(t, "cpu-endorsement", CollateralAMDVCEKV1Format, amdVCEKCollateral{VCEKDERBase64: base64.StdEncoding.EncodeToString([]byte("vcek der")), CertChainPEM: "chain"}),
			testCollateralEntry(t, "cpu-crl", CollateralAMDCRLV1Format, amdCRLCollateral{CRLDERBase64: base64.StdEncoding.EncodeToString([]byte("crl der"))}),
		},
	}
	en, err := doc.CPUEndorsements()
	require.NoError(t, err)
	assert.Equal(t, &AMDVCEK{VCEKDER: []byte("vcek der"), CertChainPEM: "chain"}, en.AMDVCEK)
	assert.Equal(t, &AMDCRL{CRLDER: []byte("crl der")}, en.AMDCRL)
	assert.Nil(t, en.IntelPCS)
}

func TestCPUEndorsementsDecodesTDXCollateral(t *testing.T) {
	url := "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	headers := map[string][]string{"Sgx-Enclave-Identity-Issuer-Chain": {"chain"}}
	body := []byte(`{"enclaveIdentity":{}}`)
	pcs := intelPCSCollateral{Responses: []rawPCSResponse{{URL: url, Headers: headers, BodyBase64: base64.StdEncoding.EncodeToString(body)}}}
	doc := &Document{
		evidence:   CPUEvidence{Format: TDXQuoteV1Format},
		collateral: []CollateralEntry{testCollateralEntry(t, "pcs", CollateralIntelPCSV1Format, pcs)},
	}
	en, err := doc.CPUEndorsements()
	require.NoError(t, err)
	assert.Equal(t, &IntelPCS{Responses: []PCSResponse{{URL: url, Headers: headers, Body: body}}}, en.IntelPCS)
	assert.Nil(t, en.AMDVCEK)
	assert.Nil(t, en.AMDCRL)
}

func TestCPUEndorsementsRejectsMalformedIntelPCS(t *testing.T) {
	malformed := CollateralEntry{ID: "pcs", Role: RoleEndorsement, Format: CollateralIntelPCSV1Format, Subjects: []string{SubjectCPU}, Data: []byte(`{"unknown":1}`)}
	doc := &Document{
		evidence:   CPUEvidence{Format: TDXQuoteV1Format},
		collateral: []CollateralEntry{malformed},
	}
	_, err := doc.CPUEndorsements()
	assert.ErrorContains(t, err, `parsing intel-pcs collateral entry "pcs"`)
}

func TestCPUEndorsementsLeavesMissingCollateralNil(t *testing.T) {
	for _, format := range []string{SEVSNPReportV1Format, TDXQuoteV1Format} {
		doc := &Document{evidence: CPUEvidence{Format: format}}
		en, err := doc.CPUEndorsements()
		require.NoError(t, err, "absence is for Authenticate to reject")
		assert.Equal(t, CPUEndorsements{}, en)
	}
}

func TestCPUEndorsementsIgnoresOtherPlatformCollateral(t *testing.T) {
	// A malformed entry for the other platform is never decoded.
	malformed := CollateralEntry{ID: "vcek", Role: RoleEndorsement, Format: CollateralAMDVCEKV1Format, Subjects: []string{SubjectCPU}, Data: []byte(`{"unknown":1}`)}
	doc := &Document{
		evidence:   CPUEvidence{Format: TDXQuoteV1Format},
		collateral: []CollateralEntry{malformed},
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
				evidence: CPUEvidence{Format: SEVSNPReportV1Format},
				collateral: []CollateralEntry{
					testCollateralEntry(t, "cpu-endorsement", CollateralAMDVCEKV1Format, amdVCEKCollateral{VCEKDERBase64: tt.vcek, CertChainPEM: "chain"}),
					testCollateralEntry(t, "cpu-crl", CollateralAMDCRLV1Format, amdCRLCollateral{CRLDERBase64: tt.crl}),
				},
			}
			_, err := doc.CPUEndorsements()
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestCPUEndorsementsRejectsNonCanonicalPCSBody(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"tcbInfo":{"tcbEvaluationDataNumber":19}}`))
	pcs := intelPCSCollateral{Responses: []rawPCSResponse{{
		URL:        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000",
		BodyBase64: encoded[:8] + "\n" + encoded[8:],
	}}}
	doc := &Document{
		evidence:   CPUEvidence{Format: TDXQuoteV1Format},
		collateral: []CollateralEntry{testCollateralEntry(t, "pcs", CollateralIntelPCSV1Format, pcs)},
	}
	_, err := doc.CPUEndorsements()
	assert.ErrorContains(t, err, "body_base64 is not canonical base64")
}

// Every captured response is decoded when the endorsements are read, not only
// the ones the verification library later requests: a malformed body in an
// otherwise unused response still rejects.
func TestCPUEndorsementsDecodesEveryPCSBody(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte(`{"tcbInfo":{}}`))
	unused := base64.StdEncoding.EncodeToString([]byte(`{"unused":true}`))
	pcs := intelPCSCollateral{Responses: []rawPCSResponse{
		{URL: "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000", BodyBase64: good},
		{URL: "https://example.com/never-requested", BodyBase64: unused[:4] + "\n" + unused[4:]},
	}}
	doc := &Document{
		evidence:   CPUEvidence{Format: TDXQuoteV1Format},
		collateral: []CollateralEntry{testCollateralEntry(t, "pcs", CollateralIntelPCSV1Format, pcs)},
	}
	_, err := doc.CPUEndorsements()
	assert.ErrorContains(t, err, `intel-pcs collateral entry "pcs" response 1`)
	assert.ErrorContains(t, err, "body_base64 is not canonical base64")
}
