package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testNonce() []byte {
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	return nonce
}

// buildTestDocumentV3 assembles a well-formed document around a dummy quote
// so envelope logic can be tested without hardware. This is a test-local
// reimplementation of what production builders (cvmimage) do: serialize the
// endorsed sections once, hash those bytes, base64-wrap them, and walk the
// REPORT_DATA ladder.
func buildTestDocumentV3(t *testing.T, nonce []byte) (*DocumentV3, []byte) {
	t.Helper()
	cryptoMaterial := CryptoMaterialSection{
		Format: CryptoMaterialV1Format,
		Items: []CryptoMaterialItem{
			{ID: CryptoMaterialIDTLS, Format: KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))},
			{ID: CryptoMaterialIDHPKE, Format: KeyX25519HPKEV1Format, Data: hex.EncodeToString(bytes.Repeat([]byte{0xbb}, 32))},
		},
	}
	deviceEvidence := DeviceEvidenceSection{
		Format: DeviceEvidenceV1Format,
		Items:  []DeviceEvidenceItem{},
	}

	cryptoBytes, err := json.Marshal(cryptoMaterial)
	require.NoError(t, err)
	deviceBytes, err := json.Marshal(deviceEvidence)
	require.NoError(t, err)
	cryptoHash := sha256.Sum256(cryptoBytes)
	deviceHash := sha256.Sum256(deviceBytes)
	reportData, err := ComputeReportDataV3(nonce, cryptoHash[:], deviceHash[:])
	require.NoError(t, err)

	doc := &DocumentV3{
		Format: AttestationV3Format,
		Challenge: ChallengeV3{
			Nonce:               hex.EncodeToString(nonce),
			ReportData:          hex.EncodeToString(reportData[:]),
			ReportDataAlgorithm: ReportDataV1Algorithm,
		},
		CPUEvidence: CPUEvidenceV3{
			Format:       SEVSNPReportV1Format,
			ReportBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 1184)),
			Endorsed: EndorsedHashesV3{
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

func TestBuildAndVerifyEnvelopeV3(t *testing.T) {
	nonce := testNonce()
	built, docBytes := buildTestDocumentV3(t, nonce)

	doc, reportData, err := VerifyEnvelopeV3(docBytes, nonce)
	require.NoError(t, err)
	assert.Equal(t, built.Challenge.ReportData, hex.EncodeToString(reportData[:]))
	assert.Equal(t, AttestationV3Format, doc.Format)

	items := doc.CryptoMaterialItems()
	require.Len(t, items, 2)
	assert.Equal(t, CryptoMaterialIDTLS, items[0].ID)
	tls, ok := doc.CryptoMaterialItem(CryptoMaterialIDTLS)
	require.True(t, ok)
	assert.Equal(t, KeySPKIFPSHA256V1Format, tls.Format)

	assert.Empty(t, doc.DeviceEvidenceItems())
}

func TestVerifyEnvelopeV3NonceMismatch(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	other := testNonce()
	other[0] ^= 0xff
	_, _, err := VerifyEnvelopeV3(docBytes, other)
	assert.ErrorContains(t, err, "nonce")
}

// mutateCryptoSection decodes the document's crypto_material, applies mutate
// to the section bytes, re-encodes the result without updating the endorsed
// hashes, and returns the re-marshaled document bytes.
func mutateCryptoSection(t *testing.T, docBytes []byte, mutate func([]byte) []byte) []byte {
	t.Helper()
	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	var encoded string
	require.NoError(t, json.Unmarshal(loose["crypto_material"], &encoded))
	section, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	reencoded, err := json.Marshal(base64.StdEncoding.EncodeToString(mutate(section)))
	require.NoError(t, err)
	loose["crypto_material"] = reencoded
	out, err := json.Marshal(loose)
	require.NoError(t, err)
	return out
}

// TestVerifyEnvelopeV3TransportedBytes verifies the endorsed hashes cover the
// builder's exact section bytes: any change to the decoded section — even
// JSON-equivalent whitespace — must break the hash binding.
func TestVerifyEnvelopeV3TransportedBytes(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	tampered := mutateCryptoSection(t, docBytes, func(section []byte) []byte {
		return bytes.Replace(section, []byte(`{"format"`), []byte(`{ "format"`), 1)
	})
	require.NotEqual(t, docBytes, tampered)

	_, _, err := VerifyEnvelopeV3(tampered, nonce)
	assert.ErrorContains(t, err, "crypto_material hash")
}

func TestVerifyEnvelopeV3TamperedKey(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	tampered := mutateCryptoSection(t, docBytes, func(section []byte) []byte {
		return bytes.Replace(section,
			[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))),
			[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xac}, 32))), 1)
	})
	require.NotEqual(t, docBytes, tampered)

	_, _, err := VerifyEnvelopeV3(tampered, nonce)
	assert.ErrorContains(t, err, "crypto_material hash")
}

func TestVerifyEnvelopeV3RejectsUnknownTopLevelMembers(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	loose["generated_at"] = json.RawMessage(`"2026-01-01T00:00:00Z"`)
	tampered, err := json.Marshal(loose)
	require.NoError(t, err)

	_, _, err = VerifyEnvelopeV3(tampered, nonce)
	assert.Error(t, err)
}

func TestVerifyEnvelopeV3RejectsUnknownAlgorithm(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	tampered := bytes.Replace(docBytes,
		[]byte(ReportDataV1Algorithm),
		[]byte("https://tinfoil.sh/report-data/v2"), 1)
	_, _, err := VerifyEnvelopeV3(tampered, nonce)
	assert.ErrorContains(t, err, "report_data_algorithm")
}

func TestParseDocumentV3RejectsDuplicateItemIDs(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	// Duplicate the tls entry inside the decoded section (the endorsed hash
	// no longer matters because parsing rejects first).
	filler := hex.EncodeToString(bytes.Repeat([]byte{0xcc}, 32))
	dup := mutateCryptoSection(t, docBytes, func(section []byte) []byte {
		return bytes.Replace(section,
			[]byte(`"items":[{"id":"tls"`),
			[]byte(`"items":[{"id":"tls","format":"`+KeySPKIFPSHA256V1Format+`","data":"`+filler+`"},{"id":"tls"`), 1)
	})
	require.NotEqual(t, docBytes, dup)

	_, err := ParseDocumentV3(dup)
	assert.ErrorContains(t, err, `duplicate crypto_material item id "tls"`)
}

func TestParseDocumentV3RejectsMalformedKeyMaterial(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	// Known key formats must carry exactly 32 bytes of lowercase hex; a
	// truncated TLS fingerprint is rejected at parse time.
	short := mutateCryptoSection(t, docBytes, func(section []byte) []byte {
		return bytes.Replace(section,
			[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))),
			[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 8))), 1)
	})
	require.NotEqual(t, docBytes, short)
	_, err := ParseDocumentV3(short)
	assert.ErrorContains(t, err, "must be 32 bytes")
}

func TestParseDocumentV3RejectsUppercaseHex(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	doc, err := ParseDocumentV3(docBytes)
	require.NoError(t, err)
	upper := bytes.Replace(docBytes, []byte(doc.Challenge.Nonce), bytes.ToUpper([]byte(doc.Challenge.Nonce)), 1)
	_, err = ParseDocumentV3(upper)
	assert.ErrorContains(t, err, "lowercase hex")
}

func TestParseDocumentV3RejectsCaseMismatchedMembers(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	// encoding/json alone would fill Format from "FORMAT" case-insensitively
	// (last member wins) without any error; strict parsing must reject it.
	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	loose["FORMAT"] = loose["format"]
	tampered, err := json.Marshal(loose)
	require.NoError(t, err)

	_, err = ParseDocumentV3(tampered)
	assert.ErrorContains(t, err, `unknown object member "FORMAT"`)
}

func TestParseDocumentV3RejectsDuplicateMembers(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	dup := bytes.Replace(docBytes,
		[]byte(`{"format"`),
		[]byte(`{"format":"`+AttestationV3Format+`","format"`), 1)
	require.NotEqual(t, docBytes, dup)

	_, err := ParseDocumentV3(dup)
	assert.ErrorContains(t, err, `duplicate object member "format"`)
}

func TestParseDocumentV3RejectsDuplicateMembersInCollateralData(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	// Collateral data is an opaque json.RawMessage, but duplicate member
	// names are still rejected inside it: those bytes are attacker-chosen
	// and duplicates parse differently across languages.
	dup := bytes.Replace(docBytes,
		[]byte(`"cert_chain_pem":""`),
		[]byte(`"vcek_der_base64":""`), 1)
	require.NotEqual(t, docBytes, dup)

	_, err := ParseDocumentV3(dup)
	assert.ErrorContains(t, err, `duplicate object member "vcek_der_base64"`)
}

func TestParseDocumentV3RejectsNonCanonicalBase64(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

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

	_, err = ParseDocumentV3(tampered)
	assert.ErrorContains(t, err, "crypto_material is not canonical base64")
}

func TestParseDocumentV3RejectsOddLengthUnknownFormatData(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	insert := func(item string) []byte {
		return mutateCryptoSection(t, docBytes, func(section []byte) []byte {
			return bytes.Replace(section,
				[]byte(`"items":[`),
				[]byte(`"items":[`+item+`,`), 1)
		})
	}

	// "abc" matches the lowercase-hex character class but is not decodable.
	_, err := ParseDocumentV3(insert(`{"id":"x","format":"https://example.com/key/v9","data":"abc"}`))
	assert.ErrorContains(t, err, `crypto_material item "x" data is not lowercase hex`)

	_, err = ParseDocumentV3(insert(`{"id":"x","format":"https://example.com/key/v9","data":""}`))
	assert.ErrorContains(t, err, `crypto_material item "x" data is empty`)
}

func TestParseDocumentV3RejectsDuplicateCollateralIDs(t *testing.T) {
	nonce := testNonce()
	doc, _ := buildTestDocumentV3(t, nonce)

	doc.Collateral = append(doc.Collateral, CollateralEntry{
		ID:     doc.Collateral[0].ID,
		Role:   RoleReferenceValues,
		Format: CollateralSigstoreCodeV1Format,
		Data:   json.RawMessage(`{}`),
	})
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)

	_, err = ParseDocumentV3(docBytes)
	assert.ErrorContains(t, err, `duplicate collateral entry id "cpu-endorsement"`)
}

func TestParseDocumentV3RejectsInvalidUTF8(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	tampered := bytes.Replace(docBytes, []byte("cpu-endorsement"), []byte("cpu-endors\xffment"), 1)
	require.NotEqual(t, docBytes, tampered)

	_, err := ParseDocumentV3(tampered)
	assert.ErrorContains(t, err, "not valid UTF-8")
}

func TestComputeReportDataV3(t *testing.T) {
	nonce := testNonce()
	cmHash := sha256.Sum256([]byte("crypto"))
	deHash := sha256.Sum256([]byte("device"))

	got, err := ComputeReportDataV3(nonce, cmHash[:], deHash[:])
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

	_, err = ComputeReportDataV3(nonce[:16], cmHash[:], deHash[:])
	assert.Error(t, err)
}

func TestDocumentV3RoundTripPreservesEndorsedBytes(t *testing.T) {
	nonce := testNonce()
	built, docBytes := buildTestDocumentV3(t, nonce)

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

func TestPCSReplayGetter(t *testing.T) {
	body := []byte(`{"tcbInfo":{"tcbEvaluationDataNumber":19}}`)
	getter, err := newPCSReplayGetter([]PCSResponse{{
		URL:        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000&tcbEvaluationDataNumber=19",
		Headers:    map[string][]string{"tcb-info-issuer-chain": {"chain"}},
		BodyBase64: base64.StdEncoding.EncodeToString(body),
	}})
	require.NoError(t, err)

	// The library requests the same resource without the
	// tcbEvaluationDataNumber parameter; the capture must still answer.
	headers, got, err := getter.Get("https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000")
	require.NoError(t, err)
	assert.Equal(t, body, got)
	assert.Equal(t, []string{"chain"}, headers["Tcb-Info-Issuer-Chain"])

	_, _, err = getter.Get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity")
	assert.ErrorContains(t, err, "no captured response")
}

func TestTCBEvaluationRecorder(t *testing.T) {
	inner, err := newPCSReplayGetter([]PCSResponse{
		{
			URL:        "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000",
			BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{"tcbInfo":{"tcbEvaluationDataNumber":20}}`)),
		},
		{
			URL:        "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity",
			BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{"enclaveIdentity":{"tcbEvaluationDataNumber":19}}`)),
		},
	})
	require.NoError(t, err)
	recorder := &tcbEvaluationRecorder{inner: inner}

	_, err = recorder.minimum()
	assert.Error(t, err)

	_, _, err = recorder.Get("https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=90c06f000000")
	require.NoError(t, err)
	_, _, err = recorder.Get("https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity")
	require.NoError(t, err)

	n, err := recorder.minimum()
	require.NoError(t, err)
	assert.Equal(t, 19, n)
}
