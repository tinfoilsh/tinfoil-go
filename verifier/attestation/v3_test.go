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
// endorsed sections once, hash the transported bytes, and walk the
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
		CryptoMaterial: json.RawMessage(cryptoBytes),
		DeviceEvidence: json.RawMessage(deviceBytes),
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

// TestVerifyEnvelopeV3TransportedBytes verifies the endorsed sections are
// hashed as transmitted: any change to the section bytes — even
// JSON-equivalent whitespace — must break the hash binding.
func TestVerifyEnvelopeV3TransportedBytes(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	// Inserting JSON-equivalent whitespace inside the section changes the
	// transported bytes and must break the hash binding.
	tampered := bytes.Replace(docBytes,
		[]byte(`"crypto_material":{"format"`),
		[]byte(`"crypto_material":{ "format"`), 1)
	require.NotEqual(t, docBytes, tampered)

	_, _, err := VerifyEnvelopeV3(tampered, nonce)
	assert.ErrorContains(t, err, "crypto_material hash")
}

func TestVerifyEnvelopeV3TamperedKey(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	tampered := bytes.Replace(docBytes,
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))),
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xac}, 32))), 1)
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

	// Duplicate the tls entry (raw byte surgery keeps the rest intact; the
	// endorsed hash no longer matters because parsing rejects first).
	filler := hex.EncodeToString(bytes.Repeat([]byte{0xcc}, 32))
	dup := bytes.Replace(docBytes,
		[]byte(`"items":[{"id":"tls"`),
		[]byte(`"items":[{"id":"tls","format":"`+KeySPKIFPSHA256V1Format+`","data":"`+filler+`"},{"id":"tls"`), 1)
	require.NotEqual(t, docBytes, dup)

	_, err := ParseDocumentV3(dup)
	assert.ErrorContains(t, err, `duplicate crypto_material item id "tls"`)
}

func TestParseDocumentV3RejectsMalformedKeyMaterial(t *testing.T) {
	nonce := testNonce()
	_, docBytes := buildTestDocumentV3(t, nonce)

	// Known key formats must carry exactly 32 bytes of lowercase hex; a
	// truncated TLS fingerprint is rejected at parse time.
	short := bytes.Replace(docBytes,
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))),
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 8))), 1)
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

func TestComputeReportDataV3(t *testing.T) {
	nonce := testNonce()
	cmHash := sha256.Sum256([]byte("crypto"))
	deHash := sha256.Sum256([]byte("device"))

	got, err := ComputeReportDataV3(nonce, cmHash[:], deHash[:])
	require.NoError(t, err)

	h := sha256.New()
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

	// The marshaled document must embed the exact endorsed bytes that were
	// hashed at build time.
	var loose map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(docBytes, &loose))
	cmHash := sha256.Sum256(loose["crypto_material"])
	assert.Equal(t, built.CPUEvidence.Endorsed.CryptoMaterialHash, hex.EncodeToString(cmHash[:]))
	deHash := sha256.Sum256(loose["device_evidence"])
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
