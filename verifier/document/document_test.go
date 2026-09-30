package document

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/errs"
)

func testNonce() []byte {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

// buildTestDocument assembles a well-formed document around a dummy quote
// so document logic can be tested without hardware. This is a test-local
// reimplementation of what production builders (cvmimage) do: serialize the
// endorsed sections once, hash those bytes, base64-wrap them, and walk the
// REPORT_DATA ladder.
func buildTestDocument(t *testing.T, nonce []byte) (*rawDocument, []byte) {
	t.Helper()
	cryptoMaterial := cryptoMaterialSection{
		Format: CryptoMaterialV1Format,
		Items: []CryptoMaterialItem{
			{ID: CryptoMaterialIDTLS, Format: KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))},
			{ID: CryptoMaterialIDHPKE, Format: KeyX25519HPKEV1Format, Data: hex.EncodeToString(bytes.Repeat([]byte{0xbb}, 32))},
		},
	}
	deviceEvidence := deviceEvidenceSection{
		Format: DeviceEvidenceV1Format,
		Items:  []DeviceEvidenceItem{},
	}

	cryptoBytes, err := json.Marshal(cryptoMaterial)
	require.NoError(t, err)
	deviceBytes, err := json.Marshal(deviceEvidence)
	require.NoError(t, err)
	cryptoHash := sha256.Sum256(cryptoBytes)
	deviceHash := sha256.Sum256(deviceBytes)
	reportData, err := ComputeReportData(nonce, cryptoHash[:], deviceHash[:])
	require.NoError(t, err)

	doc := &rawDocument{
		Format: AttestationV3Format,
		Challenge: challenge{
			Nonce:               hex.EncodeToString(nonce),
			ReportData:          hex.EncodeToString(reportData[:]),
			ReportDataAlgorithm: ReportDataV1Algorithm,
		},
		CPUEvidence: rawCPUEvidence{
			Format:       SEVSNPReportV1Format,
			ReportBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 1184)),
			Endorsed: endorsedHashes{
				CryptoMaterialHash: hex.EncodeToString(cryptoHash[:]),
				DeviceEvidenceHash: hex.EncodeToString(deviceHash[:]),
			},
		},
		CryptoMaterial: base64.StdEncoding.EncodeToString(cryptoBytes),
		DeviceEvidence: base64.StdEncoding.EncodeToString(deviceBytes),
		Collateral: []CollateralEntry{
			{
				ID:       "cpu-endorsement",
				Role:     RoleEndorsement,
				Format:   CollateralAMDVCEKV1Format,
				Subjects: []string{SubjectCPU},
				Data:     json.RawMessage(`{"vcek_der_base64":"","cert_chain_pem":""}`),
			},
		},
	}
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)
	return doc, docBytes
}

func TestBuildAndVerify(t *testing.T) {
	nonce := testNonce()
	built, docBytes := buildTestDocument(t, nonce)

	doc, err := Parse(docBytes, nonce)
	require.NoError(t, err)
	reportData, ok := doc.ExpectedReportData()
	require.True(t, ok)
	assert.Equal(t, built.Challenge.ReportData, hex.EncodeToString(reportData[:]))

	items := doc.CryptoMaterialItems()
	require.Len(t, items, 2)
	assert.Equal(t, CryptoMaterialIDTLS, items[0].ID)
	tls, ok := doc.CryptoMaterialItem(CryptoMaterialIDTLS)
	require.True(t, ok)
	assert.Equal(t, KeySPKIFPSHA256V1Format, tls.Format)
	original := *tls
	items[0].Data = "changed"
	tls.Data = "changed again"
	assert.Equal(t, original, doc.CryptoMaterialItems()[0])
	tls, ok = doc.CryptoMaterialItem(CryptoMaterialIDTLS)
	require.True(t, ok)
	assert.Equal(t, original, *tls)

	assert.Empty(t, doc.DeviceEvidenceItems())
}

func TestExpectedReportDataRequiresParse(t *testing.T) {
	for _, doc := range []*Document{nil, {}} {
		reportData, ok := doc.ExpectedReportData()
		assert.False(t, ok, "a document that did not come from Parse has no expected REPORT_DATA")
		assert.Equal(t, [64]byte{}, reportData)
	}
}

func TestCPUEvidenceClone(t *testing.T) {
	original := CPUEvidence{Format: TDXQuoteV1Format, Report: []byte("quote")}
	clone := original.Clone()
	assert.Equal(t, original, clone)
	clone.Report[0] = '!'
	assert.Equal(t, []byte("quote"), original.Report, "a clone shares no memory with its source")
	assert.Nil(t, CPUEvidence{}.Clone().Report)
}

func TestCPUEvidenceReturnsCopies(t *testing.T) {
	doc := &Document{evidence: CPUEvidence{Format: SEVSNPReportV1Format, Report: []byte("report")}}
	evidence := doc.CPUEvidence()
	evidence.Report[0] = '!'
	assert.Equal(t, []byte("report"), doc.CPUEvidence().Report, "callers must not reach the parsed report")
}

func TestDeviceEvidenceItemsReturnsCopies(t *testing.T) {
	doc := &Document{deviceEvidence: &deviceEvidenceSection{Items: []DeviceEvidenceItem{
		{ID: "gpu", Evidence: []byte(`{"nonce":"original"}`)},
	}}}
	items := doc.DeviceEvidenceItems()
	items[0].ID = "changed"
	items[0].Evidence[0] = '!'
	again := doc.DeviceEvidenceItems()
	assert.Equal(t, "gpu", again[0].ID)
	assert.Equal(t, `{"nonce":"original"}`, string(again[0].Evidence))
}

func TestVerifyNonceMismatch(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	other := testNonce()
	other[0] ^= 0xff
	_, err := Parse(docBytes, other)
	assert.ErrorContains(t, err, "challenge nonce does not match the expected nonce")
}

func TestParseRejectsWrongNonceLength(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	for _, n := range [][]byte{nil, nonce[:NonceSize-1], append(bytes.Clone(nonce), 0)} {
		_, err := Parse(docBytes, n)
		var config *errs.ConfigurationError
		require.ErrorAs(t, err, &config, "nonce of %d bytes", len(n))
	}
}

// mutateSection decodes the document's endorsed section field, applies mutate
// to the section bytes, re-encodes the result without updating the endorsed
// hashes, and returns the re-marshaled document bytes.
func mutateSection(t *testing.T, docBytes []byte, field string, mutate func([]byte) []byte) []byte {
	t.Helper()
	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	var encoded string
	require.NoError(t, json.Unmarshal(loose[field], &encoded))
	section, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	reencoded, err := json.Marshal(base64.StdEncoding.EncodeToString(mutate(section)))
	require.NoError(t, err)
	loose[field] = reencoded
	out, err := json.Marshal(loose)
	require.NoError(t, err)
	return out
}

func mutateCryptoSection(t *testing.T, docBytes []byte, mutate func([]byte) []byte) []byte {
	t.Helper()
	return mutateSection(t, docBytes, "crypto_material", mutate)
}

func TestVerifyTamperedDeviceEvidence(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	tampered := mutateSection(t, docBytes, "device_evidence", func(section []byte) []byte {
		return bytes.Replace(section, []byte(`{"format"`), []byte(`{ "format"`), 1)
	})
	require.NotEqual(t, docBytes, tampered)

	_, err := Parse(tampered, nonce)
	assert.ErrorContains(t, err, "device_evidence hash does not match")
}

// TestVerifyReportDataMismatch changes only challenge.report_data: both
// section hashes still match, so the REPORT_DATA recomputation is what must
// reject.
func TestVerifyReportDataMismatch(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	var challenge map[string]string
	require.NoError(t, json.Unmarshal(loose["challenge"], &challenge))
	challenge["report_data"] = hex.EncodeToString(bytes.Repeat([]byte{0x11}, 64))
	var err error
	loose["challenge"], err = json.Marshal(challenge)
	require.NoError(t, err)
	tampered, err := json.Marshal(loose)
	require.NoError(t, err)

	_, err = Parse(tampered, nonce)
	assert.ErrorContains(t, err, "challenge report_data does not match the recomputed value")
}

// TestVerifyTransportedBytes verifies the endorsed hashes cover the
// builder's exact section bytes: any change to the decoded section — even
// JSON-equivalent whitespace — must break the hash binding.
func TestVerifyTransportedBytes(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	tampered := mutateCryptoSection(t, docBytes, func(section []byte) []byte {
		return bytes.Replace(section, []byte(`{"format"`), []byte(`{ "format"`), 1)
	})
	require.NotEqual(t, docBytes, tampered)

	_, err := Parse(tampered, nonce)
	assert.ErrorContains(t, err, "crypto_material hash")
}

func TestVerifyTamperedKey(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	tampered := mutateCryptoSection(t, docBytes, func(section []byte) []byte {
		return bytes.Replace(section,
			[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))),
			[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xac}, 32))), 1)
	})
	require.NotEqual(t, docBytes, tampered)

	_, err := Parse(tampered, nonce)
	assert.ErrorContains(t, err, "crypto_material hash")
}

func TestVerifyRejectsUnknownTopLevelMembers(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	loose["generated_at"] = json.RawMessage(`"2026-01-01T00:00:00Z"`)
	tampered, err := json.Marshal(loose)
	require.NoError(t, err)

	_, err = Parse(tampered, nonce)
	assert.Error(t, err)
}

func TestVerifyRejectsUnknownAlgorithm(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	tampered := bytes.Replace(docBytes,
		[]byte(ReportDataV1Algorithm),
		[]byte("https://tinfoil.sh/report-data/v2"), 1)
	_, err := Parse(tampered, nonce)
	assert.ErrorContains(t, err, "report_data_algorithm")
}

func TestParseRejectsDuplicateItemIDs(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	// Duplicate the tls entry inside the decoded section (the endorsed hash
	// no longer matters because parsing rejects first).
	filler := hex.EncodeToString(bytes.Repeat([]byte{0xcc}, 32))
	dup := mutateCryptoSection(t, docBytes, func(section []byte) []byte {
		return bytes.Replace(section,
			[]byte(`"items":[{"id":"tls"`),
			[]byte(`"items":[{"id":"tls","format":"`+KeySPKIFPSHA256V1Format+`","data":"`+filler+`"},{"id":"tls"`), 1)
	})
	require.NotEqual(t, docBytes, dup)

	_, err := Parse(dup, nonce)
	assert.ErrorContains(t, err, `duplicate crypto_material item id "tls"`)
}

func TestParseRejectsMalformedKeyMaterial(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	// Known key formats must carry exactly 32 bytes of lowercase hex; a
	// truncated TLS fingerprint is rejected at parse time.
	short := mutateCryptoSection(t, docBytes, func(section []byte) []byte {
		return bytes.Replace(section,
			[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))),
			[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 8))), 1)
	})
	require.NotEqual(t, docBytes, short)
	_, err := Parse(short, nonce)
	assert.ErrorContains(t, err, "must be 32 bytes")
}

func TestParseRejectsUppercaseHex(t *testing.T) {
	nonce := testNonce()
	built, docBytes := buildTestDocument(t, nonce)

	upper := bytes.Replace(docBytes, []byte(built.Challenge.Nonce), bytes.ToUpper([]byte(built.Challenge.Nonce)), 1)
	_, err := Parse(upper, nonce)
	assert.ErrorContains(t, err, "lowercase hex")
}

func TestParseRejectsNonCanonicalBase64(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	// Insert a newline into the crypto_material base64: the decoded bytes
	// (and thus the endorsed hash) are unchanged, so acceptance would mean
	// two distinct documents with identical endorsed content.
	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	var encoded string
	require.NoError(t, json.Unmarshal(loose["crypto_material"], &encoded))
	mangled, err := json.Marshal(encoded[:8] + "\n" + encoded[8:])
	require.NoError(t, err)
	loose["crypto_material"] = mangled
	tampered, err := json.Marshal(loose)
	require.NoError(t, err)

	_, err = Parse(tampered, nonce)
	assert.ErrorContains(t, err, "crypto_material is not canonical base64")
}

func TestParseRejectsNonCanonicalReportBase64(t *testing.T) {
	nonce := testNonce()
	built, docBytes := buildTestDocument(t, nonce)
	encoded := built.CPUEvidence.ReportBase64
	require.True(t, strings.HasSuffix(encoded, "AQE="))

	// Each variant decodes to the same report bytes as the original.
	for name, variant := range map[string]string{
		"embedded newline":     encoded[:8] + "\n" + encoded[8:],
		"trailing CRLF":        encoded + "\r\n",
		"nonzero padding bits": strings.TrimSuffix(encoded, "AQE=") + "AQF=",
	} {
		t.Run(name, func(t *testing.T) {
			original, err := json.Marshal(encoded)
			require.NoError(t, err)
			replacement, err := json.Marshal(variant)
			require.NoError(t, err)
			tampered := bytes.Replace(docBytes, original, replacement, 1)
			require.NotEqual(t, docBytes, tampered)

			_, err = Parse(tampered, nonce)
			assert.ErrorContains(t, err, "cpu_evidence.report_base64")
		})
	}
}

func TestParseRejectsOddLengthUnknownFormatData(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocument(t, nonce)

	insert := func(item string) []byte {
		return mutateCryptoSection(t, docBytes, func(section []byte) []byte {
			return bytes.Replace(section,
				[]byte(`"items":[`),
				[]byte(`"items":[`+item+`,`), 1)
		})
	}

	// "abc" matches the lowercase-hex character class but is not decodable.
	_, err := Parse(insert(`{"id":"x","format":"https://example.com/key/v9","data":"abc"}`), nonce)
	assert.ErrorContains(t, err, `crypto_material item "x" data is not lowercase hex`)

	_, err = Parse(insert(`{"id":"x","format":"https://example.com/key/v9","data":""}`), nonce)
	assert.ErrorContains(t, err, `crypto_material item "x" data is empty`)
}

func TestParseRejectsDuplicateCollateralIDs(t *testing.T) {
	nonce := testNonce()
	doc, _ := buildTestDocument(t, nonce)

	doc.Collateral = append(doc.Collateral, CollateralEntry{
		ID:     doc.Collateral[0].ID,
		Role:   RoleReferenceValues,
		Format: CollateralSigstoreCodeV1Format,
		Data:   json.RawMessage(`{}`),
	})
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	_, err = Parse(docBytes, nonce)
	assert.ErrorContains(t, err, `duplicate collateral entry id "cpu-endorsement"`)
}

func TestFreshnessSelectsArtifactID(t *testing.T) {
	doc := &Document{collateral: []CollateralEntry{
		{
			ID:     FreshnessCollateralIDCode,
			Role:   RoleReferenceValues,
			Format: CollateralSigstoreFreshnessV1Format,
			Data:   json.RawMessage(`{"sigstore_bundle":{"mediaType":"code"}}`),
		},
		{
			ID:     FreshnessCollateralIDPlatform,
			Role:   RoleReferenceValues,
			Format: CollateralSigstoreFreshnessV1Format,
			Data:   json.RawMessage(`{"sigstore_bundle":{"mediaType":"platform"}}`),
		},
	}}

	code, err := doc.Freshness(FreshnessCollateralIDCode)
	require.NoError(t, err)
	assert.Contains(t, string(code.Bundle), "code")

	platform, err := doc.Freshness(FreshnessCollateralIDPlatform)
	require.NoError(t, err)
	assert.Contains(t, string(platform.Bundle), "platform")

	for _, id := range []string{"", "missing-freshness"} {
		_, err = doc.Freshness(id)
		assert.ErrorIs(t, err, ErrCollateralNotFound)
	}
}

func TestSigstoreReferences(t *testing.T) {
	entry := func(format, repo string) CollateralEntry {
		return CollateralEntry{
			ID:     format,
			Role:   RoleReferenceValues,
			Format: format,
			Data:   json.RawMessage(`{"repo":"` + repo + `","tag":"v1","digest":"` + strings.Repeat("ab", 32) + `","sigstore_bundle":{"mediaType":"` + repo + `"}}`),
		}
	}
	doc := &Document{collateral: []CollateralEntry{
		entry(CollateralSigstoreCodeV1Format, "org/code"),
		entry(CollateralSigstorePlatformV1Format, "org/platform"),
	}}

	code, err := doc.SigstoreCode()
	require.NoError(t, err)
	assert.Equal(t, "org/code", code.Repo)
	assert.Equal(t, "v1", code.Tag)
	assert.Equal(t, strings.Repeat("ab", 32), code.Digest)
	assert.Contains(t, string(code.Bundle), "org/code")

	platform, err := doc.SigstorePlatform()
	require.NoError(t, err)
	assert.Equal(t, "org/platform", platform.Repo)

	_, err = (&Document{}).SigstoreCode()
	assert.ErrorIs(t, err, ErrCollateralNotFound)
	_, err = (&Document{}).SigstorePlatform()
	assert.ErrorIs(t, err, ErrCollateralNotFound)

	malformed := entry(CollateralSigstoreCodeV1Format, "org/code")
	malformed.Data = json.RawMessage(`{"repo":"org/code","unknown":1}`)
	_, err = (&Document{collateral: []CollateralEntry{malformed}}).SigstoreCode()
	assert.ErrorContains(t, err, "parsing "+CollateralSigstoreCodeV1Format+" collateral entry")
	assert.NotErrorIs(t, err, ErrCollateralNotFound, "malformed is not missing")
}

func TestParseRejectsDuplicateFreshnessArtifactID(t *testing.T) {
	nonce := testNonce()
	doc, _ := buildTestDocument(t, nonce)
	entry := CollateralEntry{
		ID:     FreshnessCollateralIDCode,
		Role:   RoleReferenceValues,
		Format: CollateralSigstoreFreshnessV1Format,
		Data:   json.RawMessage(`{"sigstore_bundle":{}}`),
	}
	doc.Collateral = append(doc.Collateral, entry, entry)
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	_, err = Parse(docBytes, nonce)
	assert.ErrorContains(t, err, `duplicate collateral entry id "`+FreshnessCollateralIDCode+`"`)
}

func TestComputeReportData(t *testing.T) {
	nonce := testNonce()
	cmHash := sha256.Sum256([]byte("crypto"))
	deHash := sha256.Sum256([]byte("device"))

	got, err := ComputeReportData(nonce, cmHash[:], deHash[:])
	require.NoError(t, err)

	h := sha256.New()
	h.Write([]byte(ReportDataV1Algorithm))
	h.Write(nonce)
	h.Write(cmHash[:])
	h.Write(deHash[:])
	var want [64]byte
	copy(want[:32], h.Sum(nil))
	assert.Equal(t, want, got)
	assert.Equal(t, bytes.Repeat([]byte{0}, 32), got[32:])

	_, err = ComputeReportData(nonce[:16], cmHash[:], deHash[:])
	assert.Error(t, err)
}

func TestDocumentRoundTripPreservesEndorsedBytes(t *testing.T) {
	nonce := testNonce()
	built, docBytes := buildTestDocument(t, nonce)

	// The marshaled document must carry the exact endorsed bytes that were
	// hashed at build time, recoverable with a plain base64 decode.
	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	decode := func(field string) []byte {
		var encoded string
		require.NoError(t, json.Unmarshal(loose[field], &encoded))
		section, err := base64.StdEncoding.DecodeString(encoded)
		require.NoError(t, err)
		return section
	}
	cmHash := sha256.Sum256(decode("crypto_material"))
	assert.Equal(t, built.CPUEvidence.Endorsed.CryptoMaterialHash, hex.EncodeToString(cmHash[:]))
	deHash := sha256.Sum256(decode("device_evidence"))
	assert.Equal(t, built.CPUEvidence.Endorsed.DeviceEvidenceHash, hex.EncodeToString(deHash[:]))
}
