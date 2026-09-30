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

// documentWithCollateral decodes entries as Parse does and returns a document
// carrying them, for CPU evidence of the given format.
func documentWithCollateral(t *testing.T, evidenceFormat string, entries []CollateralEntry) *Document {
	t.Helper()
	set, err := decodeCollateral(entries)
	require.NoError(t, err)
	return &Document{evidence: CPUEvidence{Format: evidenceFormat}, collateral: set}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func sevEntries(t *testing.T) []CollateralEntry {
	t.Helper()
	return []CollateralEntry{
		testCollateralEntry(t, "cpu-endorsement", CollateralAMDVCEKV1Format, amdVCEKCollateral{VCEKDERBase64: b64("vcek der"), CertChainPEM: "chain"}),
		testCollateralEntry(t, "cpu-crl", CollateralAMDCRLV1Format, amdCRLCollateral{CRLDERBase64: b64("crl der")}),
	}
}

func TestCPUEndorsementsDecodesSEVCollateral(t *testing.T) {
	en := documentWithCollateral(t, SEVSNPReportV1Format, sevEntries(t)).CPUEndorsements()
	assert.Equal(t, &AMDVCEK{VCEKDER: []byte("vcek der"), CertChainPEM: "chain"}, en.AMDVCEK)
	assert.Equal(t, &AMDCRL{CRLDER: []byte("crl der")}, en.AMDCRL)
	assert.Nil(t, en.IntelPCS)
}

func TestCPUEndorsementsDecodesTDXCollateral(t *testing.T) {
	url := "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	headers := map[string][]string{"Sgx-Enclave-Identity-Issuer-Chain": {"chain"}}
	body := []byte(`{"enclaveIdentity":{}}`)
	pcs := intelPCSCollateral{Responses: []rawPCSResponse{{URL: url, Headers: headers, BodyBase64: base64.StdEncoding.EncodeToString(body)}}}
	doc := documentWithCollateral(t, TDXQuoteV1Format, []CollateralEntry{testCollateralEntry(t, "pcs", CollateralIntelPCSV1Format, pcs)})

	en := doc.CPUEndorsements()
	assert.Equal(t, &IntelPCS{Responses: []PCSResponse{{URL: url, Headers: headers, Body: body}}}, en.IntelPCS)
	assert.Nil(t, en.AMDVCEK)
	assert.Nil(t, en.AMDCRL)
}

func TestCPUEndorsementsSelectsEvidencePlatform(t *testing.T) {
	// A document may carry both platforms' collateral; only the evidence's
	// platform is returned.
	en := documentWithCollateral(t, TDXQuoteV1Format, sevEntries(t)).CPUEndorsements()
	assert.Equal(t, CPUEndorsements{}, en)
}

func TestCPUEndorsementsLeavesMissingCollateralNil(t *testing.T) {
	for _, format := range []string{SEVSNPReportV1Format, TDXQuoteV1Format} {
		en := documentWithCollateral(t, format, nil).CPUEndorsements()
		assert.Equal(t, CPUEndorsements{}, en, "absence is for Authenticate to reject")
	}
}

func TestCPUEndorsementsRequiresCPUSubject(t *testing.T) {
	entries := sevEntries(t)
	entries[0].Subjects = []string{"gpu0"}
	en := documentWithCollateral(t, SEVSNPReportV1Format, entries).CPUEndorsements()
	assert.Nil(t, en.AMDVCEK, "an entry for another subject does not endorse the CPU")
	assert.NotNil(t, en.AMDCRL)
}

func TestCPUEndorsementsReturnsCopies(t *testing.T) {
	doc := documentWithCollateral(t, SEVSNPReportV1Format, sevEntries(t))
	en := doc.CPUEndorsements()
	en.AMDVCEK.VCEKDER[0] = '!'
	en.AMDCRL = nil
	again := doc.CPUEndorsements()
	assert.Equal(t, []byte("vcek der"), again.AMDVCEK.VCEKDER)
	assert.NotNil(t, again.AMDCRL)
}

func TestPCSResponseCloneIsDeep(t *testing.T) {
	r := PCSResponse{URL: "u", Headers: map[string][]string{"h": {"v"}}, Body: []byte("body")}
	c := r.Clone()
	c.Headers["h"][0] = "changed"
	c.Headers["new"] = nil
	c.Body[0] = '!'
	assert.Equal(t, PCSResponse{URL: "u", Headers: map[string][]string{"h": {"v"}}, Body: []byte("body")}, r)
}

// Parse decodes every entry of a known role and format, whether or not
// verification reads it: a malformed entry is an envelope error.
func TestDecodeCollateralRejectsMalformedKnownFormats(t *testing.T) {
	good := sevEntries(t)
	unusedBody := b64(`{"unused":true}`)
	for _, tt := range []struct {
		name    string
		entries []CollateralEntry
		wantErr string
	}{
		{
			name:    "malformed intel-pcs",
			entries: []CollateralEntry{{ID: "pcs", Role: RoleEndorsement, Format: CollateralIntelPCSV1Format, Subjects: []string{SubjectCPU}, Data: []byte(`{"unknown":1}`)}},
			wantErr: `parsing intel-pcs collateral entry "pcs"`,
		},
		{
			name:    "other platform's collateral",
			entries: []CollateralEntry{{ID: "vcek", Role: RoleEndorsement, Format: CollateralAMDVCEKV1Format, Subjects: []string{SubjectCPU}, Data: []byte(`{"unknown":1}`)}},
			wantErr: `parsing amd-vcek collateral entry "vcek"`,
		},
		{
			name:    "entry for another subject",
			entries: []CollateralEntry{{ID: "vcek", Role: RoleEndorsement, Format: CollateralAMDVCEKV1Format, Subjects: []string{"gpu0"}, Data: []byte(`{"unknown":1}`)}},
			wantErr: `parsing amd-vcek collateral entry "vcek"`,
		},
		{
			name:    "non-canonical vcek",
			entries: []CollateralEntry{testCollateralEntry(t, "cpu-endorsement", CollateralAMDVCEKV1Format, amdVCEKCollateral{VCEKDERBase64: b64("vcek der") + "\n", CertChainPEM: "chain"}), good[1]},
			wantErr: `amd-vcek collateral entry "cpu-endorsement": vcek_der_base64 is not canonical base64`,
		},
		{
			name:    "non-canonical crl",
			entries: []CollateralEntry{good[0], testCollateralEntry(t, "cpu-crl", CollateralAMDCRLV1Format, amdCRLCollateral{CRLDERBase64: b64("crl der") + "\n"})},
			wantErr: `amd-crl collateral entry "cpu-crl": crl_der_base64 is not canonical base64`,
		},
		{
			name: "unused pcs response",
			entries: []CollateralEntry{testCollateralEntry(t, "pcs", CollateralIntelPCSV1Format, intelPCSCollateral{Responses: []rawPCSResponse{
				{URL: "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000", BodyBase64: b64(`{"tcbInfo":{}}`)},
				{URL: "https://example.com/never-requested", BodyBase64: unusedBody[:4] + "\n" + unusedBody[4:]},
			}})},
			wantErr: `intel-pcs collateral entry "pcs" response 1: body_base64 is not canonical base64`,
		},
		{
			name:    "malformed sigstore reference",
			entries: []CollateralEntry{{ID: "code", Role: RoleReferenceValues, Format: CollateralSigstoreCodeV1Format, Data: []byte(`{"repo":"org/code","unknown":1}`)}},
			wantErr: "parsing " + CollateralSigstoreCodeV1Format + ` collateral entry "code"`,
		},
		{
			name:    "malformed freshness witness",
			entries: []CollateralEntry{{ID: FreshnessCollateralIDCode, Role: RoleReferenceValues, Format: CollateralSigstoreFreshnessV1Format, Data: []byte(`{"unknown":1}`)}},
			wantErr: "parsing " + CollateralSigstoreFreshnessV1Format + ` collateral entry "code-freshness"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeCollateral(tt.entries)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestDecodeCollateralIgnoresUnknownFormats(t *testing.T) {
	// Unknown formats, and known formats under a role they do not serve, are
	// never decoded: only the structural checks apply to them.
	for _, entry := range []CollateralEntry{
		{ID: "future", Role: RoleEndorsement, Format: "https://tinfoil.sh/collateral/unknown/v9", Data: []byte(`{"x":1}`)},
		{ID: "config", Role: RoleReferenceValues, Format: CollateralConfigEndorsementV1Format, Data: []byte(`{"anything":true}`)},
		{ID: "misrole", Role: RoleReferenceValues, Format: CollateralAMDVCEKV1Format, Data: []byte(`{"unknown":1}`)},
	} {
		_, err := decodeCollateral([]CollateralEntry{entry})
		assert.NoError(t, err, entry.ID)
	}
}

func TestReferenceValuesReturnCopies(t *testing.T) {
	doc := documentWithCollateral(t, "", []CollateralEntry{
		{ID: "code", Role: RoleReferenceValues, Format: CollateralSigstoreCodeV1Format, Data: []byte(`{"repo":"o/r","tag":"v1","digest":"ab","sigstore_bundle":{"a":1}}`)},
		{ID: FreshnessCollateralIDCode, Role: RoleReferenceValues, Format: CollateralSigstoreFreshnessV1Format, Data: []byte(`{"sigstore_bundle":{"b":2}}`)},
	})
	code, err := doc.SigstoreCode()
	require.NoError(t, err)
	code.Bundle[0] = '!'
	witness, err := doc.Freshness(FreshnessCollateralIDCode)
	require.NoError(t, err)
	witness.Bundle[0] = '!'

	code, err = doc.SigstoreCode()
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1}`, string(code.Bundle))
	witness, err = doc.Freshness(FreshnessCollateralIDCode)
	require.NoError(t, err)
	assert.JSONEq(t, `{"b":2}`, string(witness.Bundle))
}

// A document may carry several entries for one purpose; the first wins, as it
// did before collateral was decoded at Parse. Later ones are still decoded.
func TestDecodeCollateralSelectsFirstEntryPerPurpose(t *testing.T) {
	pcs := func(id, url string) CollateralEntry {
		return testCollateralEntry(t, id, CollateralIntelPCSV1Format, intelPCSCollateral{Responses: []rawPCSResponse{{URL: url, BodyBase64: b64("body")}}})
	}
	code := func(id, repo string) CollateralEntry {
		return CollateralEntry{ID: id, Role: RoleReferenceValues, Format: CollateralSigstoreCodeV1Format, Data: []byte(`{"repo":"` + repo + `","tag":"","digest":"ab","sigstore_bundle":{}}`)}
	}
	entries := []CollateralEntry{
		testCollateralEntry(t, "vcek-1", CollateralAMDVCEKV1Format, amdVCEKCollateral{VCEKDERBase64: b64("first vcek"), CertChainPEM: "chain"}),
		testCollateralEntry(t, "vcek-2", CollateralAMDVCEKV1Format, amdVCEKCollateral{VCEKDERBase64: b64("second vcek"), CertChainPEM: "chain"}),
		testCollateralEntry(t, "crl-1", CollateralAMDCRLV1Format, amdCRLCollateral{CRLDERBase64: b64("first crl")}),
		testCollateralEntry(t, "crl-2", CollateralAMDCRLV1Format, amdCRLCollateral{CRLDERBase64: b64("second crl")}),
		pcs("pcs-1", "https://first.example"),
		pcs("pcs-2", "https://second.example"),
		code("code-1", "org/first"),
		code("code-2", "org/second"),
	}
	sev := documentWithCollateral(t, SEVSNPReportV1Format, entries).CPUEndorsements()
	assert.Equal(t, []byte("first vcek"), sev.AMDVCEK.VCEKDER)
	assert.Equal(t, []byte("first crl"), sev.AMDCRL.CRLDER)
	tdx := documentWithCollateral(t, TDXQuoteV1Format, entries)
	assert.Equal(t, "https://first.example", tdx.CPUEndorsements().IntelPCS.Responses[0].URL)
	ref, err := tdx.SigstoreCode()
	require.NoError(t, err)
	assert.Equal(t, "org/first", ref.Repo)
}

func TestEndorsementClonesPreserveNil(t *testing.T) {
	assert.Nil(t, (*AMDVCEK)(nil).Clone())
	assert.Nil(t, (*AMDCRL)(nil).Clone())
	assert.Nil(t, (*IntelPCS)(nil).Clone())
	assert.Equal(t, &IntelPCS{}, (&IntelPCS{}).Clone(), "a nil Responses stays nil")
	assert.Equal(t, PCSResponse{}, PCSResponse{}.Clone())
	assert.Equal(t, CPUEndorsements{}, CPUEndorsements{}.Clone())
}

// A reference must carry what verification needs: a bundle and a digest.
// Whether a present bundle verifies is provenance's job, and the tag is an
// optional hint.
func TestDecodeCollateralRequiresSigstoreBundleAndDigest(t *testing.T) {
	ref := func(format, data string) CollateralEntry {
		return CollateralEntry{ID: "ref", Role: RoleReferenceValues, Format: format, Data: []byte(data)}
	}
	for _, tt := range []struct {
		name    string
		entry   CollateralEntry
		wantErr string
	}{
		{"code without bundle", ref(CollateralSigstoreCodeV1Format, `{"repo":"o/r","tag":"v1","digest":"ab"}`), "is missing sigstore_bundle"},
		{"code with null bundle", ref(CollateralSigstoreCodeV1Format, `{"repo":"o/r","tag":"v1","digest":"ab","sigstore_bundle":null}`), "is missing sigstore_bundle"},
		{"platform without digest", ref(CollateralSigstorePlatformV1Format, `{"repo":"o/r","tag":"v1","sigstore_bundle":{}}`), "is missing digest"},
		{"code with empty digest", ref(CollateralSigstoreCodeV1Format, `{"repo":"o/r","tag":"v1","digest":"","sigstore_bundle":{}}`), "is missing digest"},
		{"freshness without bundle", ref(CollateralSigstoreFreshnessV1Format, `{}`), "is missing sigstore_bundle"},
		{"freshness with null bundle", ref(CollateralSigstoreFreshnessV1Format, `{"sigstore_bundle":null}`), "is missing sigstore_bundle"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeCollateral([]CollateralEntry{tt.entry})
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
	for name, entry := range map[string]CollateralEntry{
		"empty tag and repo":     ref(CollateralSigstoreCodeV1Format, `{"repo":"","tag":"","digest":"ab","sigstore_bundle":{"mediaType":"x"}}`),
		"present invalid bundle": ref(CollateralSigstoreFreshnessV1Format, `{"sigstore_bundle":{}}`),
	} {
		_, err := decodeCollateral([]CollateralEntry{entry})
		assert.NoError(t, err, name)
	}
}
