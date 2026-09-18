package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

func testRegister(digit byte) string {
	return strings.Repeat(string(digit), 96)
}

func sevPin(register string) *measurement.Measurement {
	return &measurement.Measurement{Type: measurement.SevGuestV2, Registers: []string{register}}
}

func TestNewPinCopiesAndNormalizes(t *testing.T) {
	gpus := 1
	shape := &policy.Shape{CPUs: 4, MemoryMB: 8192, Disks: 1, GPUs: &gpus}
	m := sevPin(strings.ToUpper(testRegister('a')))

	pin, err := NewPin(m, shape)
	require.NoError(t, err)
	assert.Equal(t, testRegister('a'), pin.Measurement.Registers[0])

	// Mutating the caller's inputs after construction must not change the pin.
	m.Registers[0] = testRegister('f')
	m.Type = measurement.TdxGuestV2
	shape.CPUs = 99
	*shape.GPUs = 99
	assert.Equal(t, measurement.SevGuestV2, pin.Measurement.Type)
	assert.Equal(t, testRegister('a'), pin.Measurement.Registers[0])
	assert.Equal(t, 4, pin.Shape.CPUs)
	assert.Equal(t, 1, *pin.Shape.GPUs)

	// A nil shape stays nil rather than becoming an empty shape.
	pin, err = NewPin(sevPin(testRegister('a')), nil)
	require.NoError(t, err)
	assert.Nil(t, pin.Shape)
}

// The full validation table lives in measurement/pin_test.go; this checks the
// constructor wires the validator and wraps its errors.
func TestNewPinnedSecureClientRejectsInvalidPins(t *testing.T) {
	for name, m := range map[string]*measurement.Measurement{
		"nil":            nil,
		"short register": sevPin("abc"),
		"wrong count":    {Type: measurement.TdxGuestV2, Registers: []string{testRegister('a')}},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := NewPinnedSecureClient("enclave.test", m, nil)
			assert.Error(t, err)
			assert.Nil(t, client)
		})
	}

	client, err := NewPinnedSecureClient("enclave.test", sevPin(testRegister('a')), nil)
	require.NoError(t, err)
	assert.Equal(t, "enclave.test", client.Enclave())
	assert.Equal(t, PinnedNoRepo, client.Repo())
}

func TestNewPinnedSecureClientJSON(t *testing.T) {
	measurementJSON := `{"type":"https://tinfoil.sh/predicate/sev-snp-guest/v2","registers":["` + testRegister('a') + `"]}`

	client, err := NewPinnedSecureClientJSON("enclave.test", measurementJSON, "")
	require.NoError(t, err)
	assert.Nil(t, client.pin.Shape)
	assert.Equal(t, testRegister('a'), client.pin.Measurement.Registers[0])

	client, err = NewPinnedSecureClientJSON("enclave.test", measurementJSON, `{"cpus":4,"memory_mb":8192,"disks":1}`)
	require.NoError(t, err)
	require.NotNil(t, client.pin.Shape)
	assert.Equal(t, 4, client.pin.Shape.CPUs)
	assert.Nil(t, client.pin.Shape.GPUs)

	for name, tc := range map[string][2]string{
		"invalid measurement JSON": {`{`, ""},
		"null measurement":         {`null`, ""},
		"short register":           {`{"type":"https://tinfoil.sh/predicate/sev-snp-guest/v2","registers":["abc"]}`, ""},
		"invalid shape JSON":       {measurementJSON, `not json`},
		"null shape":               {measurementJSON, `null`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewPinnedSecureClientJSON("enclave.test", tc[0], tc[1])
			assert.Error(t, err)
		})
	}
}

// pinnedTestDocument is an envelope-valid v3 document with no reference-values
// collateral. Pinned verification must reject it at the platform reference
// step: pinning removes the code-provenance requirement, not the platform one.
func pinnedTestDocument(t *testing.T, nonce []byte, format string) []byte {
	t.Helper()
	crypto := envelope.CryptoMaterialSection{
		Format: envelope.CryptoMaterialV1Format,
		Items: []envelope.CryptoMaterialItem{
			{ID: envelope.CryptoMaterialIDTLS, Format: envelope.KeySPKIFPSHA256V1Format, Data: hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32))},
		},
	}
	device := envelope.DeviceEvidenceSection{Format: envelope.DeviceEvidenceV1Format, Items: []envelope.DeviceEvidenceItem{}}
	cryptoBytes, err := json.Marshal(crypto)
	require.NoError(t, err)
	deviceBytes, err := json.Marshal(device)
	require.NoError(t, err)
	cryptoHash := sha256.Sum256(cryptoBytes)
	deviceHash := sha256.Sum256(deviceBytes)
	reportData, err := envelope.ComputeReportData(nonce, cryptoHash[:], deviceHash[:])
	require.NoError(t, err)

	doc := envelope.Document{
		Format: envelope.AttestationV3Format,
		Challenge: envelope.Challenge{
			Nonce:               hex.EncodeToString(nonce),
			ReportData:          hex.EncodeToString(reportData[:]),
			ReportDataAlgorithm: envelope.ReportDataV1Algorithm,
		},
		CPUEvidence: envelope.CPUEvidence{
			Format:       format,
			ReportBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 1184)),
			Endorsed: envelope.EndorsedHashes{
				CryptoMaterialHash: hex.EncodeToString(cryptoHash[:]),
				DeviceEvidenceHash: hex.EncodeToString(deviceHash[:]),
			},
		},
		CryptoMaterial: base64.StdEncoding.EncodeToString(cryptoBytes),
		DeviceEvidence: base64.StdEncoding.EncodeToString(deviceBytes),
	}
	docBytes, err := json.Marshal(doc)
	require.NoError(t, err)
	return docBytes
}

func TestVerifyDocumentV3PinnedStillRequiresPlatformReferenceValues(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x42}, 32)
	pin, err := NewPin(sevPin(testRegister('a')), nil)
	require.NoError(t, err)

	_, err = VerifyDocumentV3Pinned(pinnedTestDocument(t, nonce, envelope.SEVSNPReportV1Format), nonce, pin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reference values")
	assert.NotContains(t, err.Error(), "code", "pinned mode must not demand code provenance")

	// The envelope's own checks still run first.
	_, err = VerifyDocumentV3Pinned(pinnedTestDocument(t, nonce, envelope.SEVSNPReportV1Format), bytes.Repeat([]byte{0x43}, 32), pin)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "envelope")

	_, err = VerifyDocumentV3Pinned(pinnedTestDocument(t, nonce, envelope.SEVSNPReportV1Format), nonce, nil)
	assert.ErrorContains(t, err, "requires a pin")
}

func TestPinnedVerificationDocumentSkipsCodeProvenance(t *testing.T) {
	groundTruth := &GroundTruth{
		ConfigRepo:         PinnedNoRepo,
		EnclaveHost:        "enclave.test",
		Digest:             PinnedNoDigest,
		CodeMeasurement:    sevPin(testRegister('a')),
		EnclaveMeasurement: sevPin(testRegister('a')),
		TLSPublicKey:       "tls",
	}
	doc := newVerificationDocument(groundTruth)
	assert.Equal(t, "skipped", doc.Steps.FetchDigest.Status)
	assert.Equal(t, "skipped", doc.Steps.VerifyCode.Status)
	assert.Equal(t, "success", doc.Steps.VerifyEnclave.Status)
	assert.Equal(t, "success", doc.Steps.CompareMeasurements.Status)
	assert.Equal(t, PinnedNoRepo, doc.ConfigRepo)
	assert.Equal(t, PinnedNoDigest, doc.ReleaseDigest)

	// A release-verified result is unaffected.
	groundTruth.Digest = "abc123"
	assert.Equal(t, "success", newVerificationDocument(groundTruth).Steps.VerifyCode.Status)
}

// TestVerifyPinned is opt-in like TestVerify: it learns the live enclave's
// measurement through the normal v3 flow, re-verifies with that measurement
// pinned, and confirms a tampered pin is rejected at the quote comparison.
func TestVerifyPinned(t *testing.T) {
	enclave, repo := os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO")
	if enclave == "" || repo == "" {
		t.Skip("TINFOIL_ENCLAVE or TINFOIL_REPO not set")
	}

	release := NewSecureClient(enclave, repo)
	releaseTruth, err := release.Verify()
	skipIfEnclaveNotV3(t, err)
	require.NoError(t, err)
	require.NotNil(t, releaseTruth.EnclaveMeasurement)

	// A TDX pin needs the VM shape the code artifact declares, which the
	// release flow does not surface; a live TDX pin is exercised separately.
	if releaseTruth.EnclaveMeasurement.Type == measurement.TdxGuestV2 {
		t.Skip("live TDX pinning requires the code artifact's VM shape, which VerifiedDocumentV3 does not expose")
	}

	pinned, err := NewPinnedSecureClient(enclave, releaseTruth.EnclaveMeasurement, nil)
	require.NoError(t, err)
	pinnedTruth, err := pinned.Verify()
	require.NoError(t, err)
	assert.Equal(t, PinnedNoDigest, pinnedTruth.Digest)
	assert.Equal(t, PinnedNoRepo, pinnedTruth.ConfigRepo)
	assert.Empty(t, pinnedTruth.ReleaseTag)
	assert.Equal(t, releaseTruth.EnclaveFingerprint, pinnedTruth.EnclaveFingerprint)
	assert.Equal(t, releaseTruth.TLSPublicKey, pinnedTruth.TLSPublicKey)
	doc := pinned.VerificationDocument()
	assert.Equal(t, "skipped", doc.Steps.VerifyCode.Status)
	assert.Equal(t, "success", doc.Steps.VerifyEnclave.Status)

	// Returned ground truth must not alias the pin.
	pinnedTruth.CodeMeasurement.Registers[0] = testRegister('0')
	assert.NotEqual(t, testRegister('0'), pinned.pin.Measurement.Registers[0])

	tampered := cloneMeasurement(releaseTruth.EnclaveMeasurement)
	first := tampered.Registers[0]
	replacement := "0"
	if first[0] == '0' {
		replacement = "1"
	}
	tampered.Registers[0] = replacement + first[1:]
	badPin, err := NewPinnedSecureClient(enclave, tampered, nil)
	require.NoError(t, err)
	_, err = badPin.Verify()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cpu evidence")
}
