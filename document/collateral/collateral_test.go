package collateral

import (
	"encoding/base64"
	"encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testEntry(t *testing.T, id, format string, payload any) Entry {
	t.Helper()
	data, err := json.Marshal(payload)
	require.NoError(t, err)
	return Entry{ID: id, Role: RoleEndorsement, Format: format, Subjects: []string{SubjectCPU}, Data: data}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func sevEntries(t *testing.T) []Entry {
	t.Helper()
	return []Entry{
		testEntry(t, "cpu-endorsement", AMDVCEKV1Format, amdVCEKData{VCEKDERBase64: b64("vcek der"), CertChainPEM: "chain"}),
		testEntry(t, "cpu-crl", AMDCRLV1Format, amdCRLData{CRLDERBase64: b64("crl der")}),
	}
}

func decode(t *testing.T, entries []Entry) Set {
	t.Helper()
	set, err := Decode(entries)
	require.NoError(t, err)
	return set
}

func TestDecodeSEVCollateral(t *testing.T) {
	set := decode(t, sevEntries(t))
	assert.Equal(t, CPUEndorsements{
		AMDVCEK: &AMDVCEK{VCEKDER: []byte("vcek der"), CertChainPEM: "chain"},
		AMDCRL:  &AMDCRL{CRLDER: []byte("crl der")},
	}, set.CPU)
}

func TestDecodeTDXCollateral(t *testing.T) {
	url := "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"
	headers := map[string][]string{"Sgx-Enclave-Identity-Issuer-Chain": {"chain"}}
	body := []byte(`{"enclaveIdentity":{}}`)
	pcs := intelPCSData{Responses: []pcsResponseData{{URL: url, Headers: headers, BodyBase64: base64.StdEncoding.EncodeToString(body)}}}
	set := decode(t, []Entry{testEntry(t, "pcs", IntelPCSV1Format, pcs)})
	assert.Equal(t, CPUEndorsements{IntelPCS: &IntelPCS{Responses: []PCSResponse{{URL: url, Headers: headers, Body: body}}}}, set.CPU)
}

func TestDecodeEmpty(t *testing.T) {
	set := decode(t, nil)
	assert.Equal(t, CPUEndorsements{}, set.CPU)
	assert.Nil(t, set.SigstoreCode)
	assert.Nil(t, set.SigstorePlatform)
	assert.Empty(t, set.Freshness)
}

func TestDecodeRequiresCPUSubject(t *testing.T) {
	entries := sevEntries(t)
	entries[0].Subjects = []string{"gpu0"}
	set := decode(t, entries)
	assert.Nil(t, set.CPU.AMDVCEK, "an entry for another subject does not endorse the CPU")
	assert.NotNil(t, set.CPU.AMDCRL)
}

func TestDecodeRejectsMalformedEntryList(t *testing.T) {
	entry := Entry{ID: "crl", Role: RoleEndorsement, Format: "https://tinfoil.sh/collateral/unknown/v9", Data: []byte(`{}`)}
	unknownRole := entry
	unknownRole.Role = "unknown"
	withData := func(data string) []Entry {
		e := entry
		e.Data = []byte(data)
		return []Entry{e}
	}
	for _, tt := range []struct {
		name    string
		entries []Entry
		wantErr string
	}{
		{"missing id", []Entry{{Role: RoleEndorsement, Format: AMDCRLV1Format}}, "collateral entry 0 is incomplete"},
		{"missing format", []Entry{entry, {ID: "x", Role: RoleEndorsement}}, "collateral entry 1 is incomplete"},
		{"duplicate id", []Entry{entry, entry}, `duplicate collateral entry id "crl"`},
		{"unknown role", []Entry{unknownRole}, `collateral entry "crl" has unknown role "unknown"`},
		// Unknown formats are not decoded, but their data must still be an object.
		{"missing data", withData(""), `collateral entry "crl" data is not a valid JSON object`},
		{"null data", withData("null"), `collateral entry "crl" data is not a valid JSON object`},
		{"array data", withData("[]"), `collateral entry "crl" data is not a valid JSON object`},
		{"string data", withData(`"x"`), `collateral entry "crl" data is not a valid JSON object`},
		{"malformed object", withData(`{bad`), `collateral entry "crl" data is not a valid JSON object`},
		{"duplicate member", withData(`{"a":1,"a":2}`), `collateral entry "crl" data is not a valid JSON object`},
		{"trailing value", withData(`{} {}`), `collateral entry "crl" data is not a valid JSON object`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.entries)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// Decode decodes every entry of a known role and format, whether or not
// verification reads it.
func TestDecodeRejectsMalformedKnownFormats(t *testing.T) {
	good := sevEntries(t)
	unusedBody := b64(`{"unused":true}`)
	for _, tt := range []struct {
		name    string
		entries []Entry
		wantErr string
	}{
		{
			name:    "malformed intel-pcs",
			entries: []Entry{{ID: "pcs", Role: RoleEndorsement, Format: IntelPCSV1Format, Subjects: []string{SubjectCPU}, Data: []byte(`{"unknown":1}`)}},
			wantErr: `parsing intel-pcs collateral entry "pcs"`,
		},
		{
			name:    "entry for another subject",
			entries: []Entry{{ID: "vcek", Role: RoleEndorsement, Format: AMDVCEKV1Format, Subjects: []string{"gpu0"}, Data: []byte(`{"unknown":1}`)}},
			wantErr: `parsing amd-vcek collateral entry "vcek"`,
		},
		{
			name:    "non-canonical vcek",
			entries: []Entry{testEntry(t, "cpu-endorsement", AMDVCEKV1Format, amdVCEKData{VCEKDERBase64: b64("vcek der") + "\n", CertChainPEM: "chain"}), good[1]},
			wantErr: `amd-vcek collateral entry "cpu-endorsement": vcek_der_base64 is not canonical base64`,
		},
		{
			name:    "non-canonical crl",
			entries: []Entry{good[0], testEntry(t, "cpu-crl", AMDCRLV1Format, amdCRLData{CRLDERBase64: b64("crl der") + "\r\n"})},
			wantErr: `amd-crl collateral entry "cpu-crl": crl_der_base64 is not canonical base64`,
		},
		{
			name:    "invalid crl base64",
			entries: []Entry{testEntry(t, "cpu-crl", AMDCRLV1Format, amdCRLData{CRLDERBase64: "not base64!"})},
			wantErr: `amd-crl collateral entry "cpu-crl": decoding crl_der_base64`,
		},
		{
			name: "unused pcs response",
			entries: []Entry{testEntry(t, "pcs", IntelPCSV1Format, intelPCSData{Responses: []pcsResponseData{
				{URL: "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000", BodyBase64: b64(`{"tcbInfo":{}}`)},
				{URL: "https://example.com/never-requested", BodyBase64: unusedBody[:4] + "\n" + unusedBody[4:]},
			}})},
			wantErr: `intel-pcs collateral entry "pcs" response 1: body_base64 is not canonical base64`,
		},
		{
			name:    "malformed sigstore reference",
			entries: []Entry{{ID: "code", Role: RoleReferenceValues, Format: SigstoreCodeV1Format, Data: []byte(`{"repo":"org/code","unknown":1}`)}},
			wantErr: "parsing " + SigstoreCodeV1Format + ` collateral entry "code"`,
		},
		{
			name:    "malformed freshness witness",
			entries: []Entry{{ID: FreshnessIDCode, Role: RoleReferenceValues, Format: SigstoreFreshnessV1Format, Data: []byte(`{"unknown":1}`)}},
			wantErr: "parsing " + SigstoreFreshnessV1Format + ` collateral entry "code-freshness"`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.entries)
			assert.ErrorContains(t, err, tt.wantErr)
			assert.NotErrorIs(t, err, ErrNotFound, "malformed is not missing")
		})
	}
}

func TestDecodeIgnoresUnknownFormats(t *testing.T) {
	// Unknown formats, and known formats under a role they do not serve, are
	// never decoded: only the structural checks apply to them.
	for _, entry := range []Entry{
		{ID: "future", Role: RoleEndorsement, Format: "https://tinfoil.sh/collateral/unknown/v9", Data: []byte(`{"x":1}`)},
		{ID: "config", Role: RoleEndorsement, Format: ConfigEndorsementV1Format, Data: []byte(`{"anything":true}`)},
		{ID: "misrole", Role: RoleReferenceValues, Format: AMDVCEKV1Format, Data: []byte(`{"unknown":1}`)},
	} {
		set, err := Decode([]Entry{entry})
		assert.NoError(t, err, entry.ID)
		assert.Equal(t, CPUEndorsements{}, set.CPU, entry.ID)
	}
}

// A document may carry several entries for one purpose; the first wins. Later
// ones are still decoded.
func TestDecodeSelectsFirstEntryPerPurpose(t *testing.T) {
	pcs := func(id, url string) Entry {
		return testEntry(t, id, IntelPCSV1Format, intelPCSData{Responses: []pcsResponseData{{URL: url, BodyBase64: b64("body")}}})
	}
	ref := func(id, format, repo string) Entry {
		return Entry{ID: id, Role: RoleReferenceValues, Format: format, Data: []byte(`{"repo":"` + repo + `","tag":"","digest":"ab","sigstore_bundle":{}}`)}
	}
	set := decode(t, []Entry{
		testEntry(t, "vcek-1", AMDVCEKV1Format, amdVCEKData{VCEKDERBase64: b64("first vcek"), CertChainPEM: "chain"}),
		testEntry(t, "vcek-2", AMDVCEKV1Format, amdVCEKData{VCEKDERBase64: b64("second vcek"), CertChainPEM: "chain"}),
		testEntry(t, "crl-1", AMDCRLV1Format, amdCRLData{CRLDERBase64: b64("first crl")}),
		testEntry(t, "crl-2", AMDCRLV1Format, amdCRLData{CRLDERBase64: b64("second crl")}),
		pcs("pcs-1", "https://first.example"),
		pcs("pcs-2", "https://second.example"),
		ref("code-1", SigstoreCodeV1Format, "org/first"),
		ref("code-2", SigstoreCodeV1Format, "org/second"),
		ref("platform-1", SigstorePlatformV1Format, "org/first-platform"),
		ref("platform-2", SigstorePlatformV1Format, "org/second-platform"),
	})
	assert.Equal(t, []byte("first vcek"), set.CPU.AMDVCEK.VCEKDER)
	assert.Equal(t, []byte("first crl"), set.CPU.AMDCRL.CRLDER)
	assert.Equal(t, "https://first.example", set.CPU.IntelPCS.Responses[0].URL)
	assert.Equal(t, "org/first", set.SigstoreCode.Repo)
	assert.Equal(t, "org/first-platform", set.SigstorePlatform.Repo)
}

func TestDecodeKeysFreshnessByID(t *testing.T) {
	witness := func(id, bundle string) Entry {
		return Entry{ID: id, Role: RoleReferenceValues, Format: SigstoreFreshnessV1Format, Data: []byte(`{"sigstore_bundle":` + bundle + `}`)}
	}
	set := decode(t, []Entry{witness(FreshnessIDCode, `{"a":1}`), witness(FreshnessIDPlatform, `{"b":2}`)})
	assert.Equal(t, map[string]Freshness{
		FreshnessIDCode:     {Bundle: []byte(`{"a":1}`)},
		FreshnessIDPlatform: {Bundle: []byte(`{"b":2}`)},
	}, set.Freshness)
}

// A reference must carry what verification needs: a bundle and a digest.
// Whether a present bundle verifies is provenance's job, and the tag is an
// optional hint.
func TestDecodeRequiresSigstoreBundleAndDigest(t *testing.T) {
	ref := func(format, data string) Entry {
		return Entry{ID: "ref", Role: RoleReferenceValues, Format: format, Data: []byte(data)}
	}
	for _, tt := range []struct {
		name    string
		entry   Entry
		wantErr string
	}{
		{"code without bundle", ref(SigstoreCodeV1Format, `{"repo":"o/r","tag":"v1","digest":"ab"}`), "is missing sigstore_bundle"},
		{"code with null bundle", ref(SigstoreCodeV1Format, `{"repo":"o/r","tag":"v1","digest":"ab","sigstore_bundle":null}`), "is missing sigstore_bundle"},
		{"platform without digest", ref(SigstorePlatformV1Format, `{"repo":"o/r","tag":"v1","sigstore_bundle":{}}`), "is missing digest"},
		{"code with empty digest", ref(SigstoreCodeV1Format, `{"repo":"o/r","tag":"v1","digest":"","sigstore_bundle":{}}`), "is missing digest"},
		{"freshness without bundle", ref(SigstoreFreshnessV1Format, `{}`), "is missing sigstore_bundle"},
		{"freshness with null bundle", ref(SigstoreFreshnessV1Format, `{"sigstore_bundle":null}`), "is missing sigstore_bundle"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode([]Entry{tt.entry})
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
	for name, entry := range map[string]Entry{
		"empty tag and repo":     ref(SigstoreCodeV1Format, `{"repo":"","tag":"","digest":"ab","sigstore_bundle":{"mediaType":"x"}}`),
		"present invalid bundle": ref(SigstoreFreshnessV1Format, `{"sigstore_bundle":{}}`),
	} {
		_, err := Decode([]Entry{entry})
		assert.NoError(t, err, name)
	}
}

func TestPCSResponseCloneIsDeep(t *testing.T) {
	r := PCSResponse{URL: "u", Headers: map[string][]string{"h": {"v"}}, Body: []byte("body")}
	c := r.Clone()
	c.Headers["h"][0] = "changed"
	c.Headers["new"] = nil
	c.Body[0] = '!'
	assert.Equal(t, PCSResponse{URL: "u", Headers: map[string][]string{"h": {"v"}}, Body: []byte("body")}, r)
}

func TestClonesPreserveNil(t *testing.T) {
	assert.Nil(t, (*AMDVCEK)(nil).Clone())
	assert.Nil(t, (*AMDCRL)(nil).Clone())
	assert.Nil(t, (*IntelPCS)(nil).Clone())
	assert.Equal(t, &IntelPCS{}, (&IntelPCS{}).Clone(), "a nil Responses stays nil")
	assert.Equal(t, PCSResponse{}, PCSResponse{}.Clone())
	assert.Equal(t, CPUEndorsements{}, CPUEndorsements{}.Clone())
	assert.Equal(t, SigstoreRef{}, SigstoreRef{}.Clone())
	assert.Equal(t, Freshness{}, Freshness{}.Clone())
}
