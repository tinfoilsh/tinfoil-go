package client

import (
	"encoding/json"
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

func TestVerify(t *testing.T) {
	enclave := os.Getenv("TINFOIL_ENCLAVE")
	repo := os.Getenv("TINFOIL_REPO")
	if enclave == "" || repo == "" {
		t.Skip("TINFOIL_ENCLAVE or TINFOIL_REPO not set")
	}

	client := NewSecureClient(enclave, repo)
	_, err := client.Verify()
	assert.NoError(t, err)
}

func TestClientGroundTruthJSON(t *testing.T) {
	codeMeasurement := &attestation.Measurement{
		Type:      attestation.SnpTdxMultiPlatformV1,
		Registers: []string{"a", "b"},
	}
	enclaveMeasurement := &attestation.Measurement{
		Type:      attestation.TdxGuestV2,
		Registers: []string{"a"},
	}

	gt := &GroundTruth{
		TLSPublicKey:       "pubkey",
		HPKEPublicKey:      "hpkekey",
		Digest:             "feabcd",
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: enclaveMeasurement,
	}
	client := &SecureClient{
		groundTruth: gt,
	}

	encoded, err := client.GroundTruthJSON()
	assert.NoError(t, err)

	// Decode and compare
	var gt2 GroundTruth
	assert.NoError(t, json.Unmarshal([]byte(encoded), &gt2))
	assert.Equal(t, gt, &gt2)
}

func TestVerificationDocumentJSON(t *testing.T) {
	verifiedAt := time.Date(2026, time.August, 4, 12, 30, 0, 0, time.UTC).Format(time.RFC3339Nano)
	groundTruth := &GroundTruth{
		ConfigRepo:         "tinfoilsh/confidential-model-router",
		EnclaveHost:        "router.example",
		ReleaseTag:         "v1.2.3",
		TLSPublicKey:       "tls-fingerprint",
		HPKEPublicKey:      "hpke-key",
		Digest:             "release-digest",
		CodeMeasurement:    &attestation.Measurement{Type: attestation.SevGuestV2, Registers: []string{"code"}},
		EnclaveMeasurement: &attestation.Measurement{Type: attestation.SevGuestV2, Registers: []string{"enclave"}},
		CodeFingerprint:    "code-fingerprint",
		EnclaveFingerprint: "enclave-fingerprint",
		Verifier:           SoftwareIdentity{Name: verifierName, Version: "v1.0.0"},
		VerifiedAt:         verifiedAt,
	}
	client := &SecureClient{
		groundTruth:          groundTruth,
		verificationDocument: newVerificationDocument(groundTruth),
	}

	encoded, err := client.VerificationDocumentJSON()
	assert.NoError(t, err)

	var document VerificationDocument
	assert.NoError(t, json.Unmarshal([]byte(encoded), &document))
	assert.Equal(t, verificationDocumentSchemaVersion, document.SchemaVersion)
	assert.Equal(t, "tinfoilsh/confidential-model-router", document.ConfigRepo)
	assert.Equal(t, "v1.2.3", document.ReleaseTag)
	assert.Equal(t, "release-digest", document.ReleaseDigest)
	assert.Equal(t, verifierName, document.Verifier.Name)
	assert.Equal(t, "v1.0.0", document.Verifier.Version)
	assert.Equal(t, verifiedAt, document.VerifiedAt)
	assert.Equal(t, "tls-fingerprint", document.EnclaveMeasurement.TLSPublicKeyFingerprint)
	assert.True(t, document.SecurityVerified)
}

func TestVerificationDocumentStepStates(t *testing.T) {
	tests := []struct {
		name        string
		groundTruth *GroundTruth
		fetchDigest string
		verifyCode  string
	}{
		{name: "direct release", groundTruth: &GroundTruth{ReleaseTag: "v1.2.3", Digest: "digest", DigestFetched: true}, fetchDigest: "success", verifyCode: "success"},
		{name: "caller supplied bundle", groundTruth: &GroundTruth{ReleaseTag: "v1.2.3", Digest: "digest"}, fetchDigest: "skipped", verifyCode: "success"},
		{name: "pinned", groundTruth: &GroundTruth{Digest: pinnedNoDigest}, fetchDigest: "skipped", verifyCode: "skipped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document := newVerificationDocument(tt.groundTruth)
			assert.Equal(t, tt.fetchDigest, document.Steps.FetchDigest.Status)
			assert.Equal(t, tt.verifyCode, document.Steps.VerifyCode.Status)
		})
	}
}

func TestCurrentVerifierVersion(t *testing.T) {
	tests := []struct {
		name    string
		info    *debug.BuildInfo
		ok      bool
		version string
	}{
		{name: "released main module", info: &debug.BuildInfo{Main: debug.Module{Path: verifierModulePath, Version: "v1.2.3"}}, ok: true, version: "1.2.3"},
		{name: "released dependency", info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}, Deps: []*debug.Module{{Path: verifierModulePath, Version: "v2.3.4"}}}, ok: true, version: "2.3.4"},
		{name: "local replacement", info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}, Deps: []*debug.Module{{Path: verifierModulePath, Version: "v1.2.3", Replace: &debug.Module{Path: "../tinfoil-go"}}}}, ok: true, version: "devel"},
		{name: "development build", info: &debug.BuildInfo{Main: debug.Module{Path: verifierModulePath, Version: "(devel)"}}, ok: true, version: "devel"},
		{name: "missing build info", ok: false, version: "unknown"},
		{name: "module absent", info: &debug.BuildInfo{Main: debug.Module{Path: "example.com/app"}}, ok: true, version: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.version, verifierVersion(tt.info, tt.ok))
		})
	}
}

func TestVerifyFromBundleRejectsVerifiedDomainMismatch(t *testing.T) {
	client := NewSecureClient("verified.example", defaultRouterRepo)
	client.setVerifiedState(&GroundTruth{EnclaveHost: "verified.example"})

	_, err := client.VerifyFromBundle(&attestation.Bundle{Domain: "other.example"})

	assert.EqualError(t, err, `verifyBundle: domain "other.example" does not match verified enclave "verified.example"`)
	assert.Equal(t, "verified.example", client.Enclave())
	assert.Equal(t, "verified.example", client.GroundTruth().EnclaveHost)
}

func TestSetExpectedRTMR3KeepsTheVerifiedDomainPinned(t *testing.T) {
	client := NewSecureClient("verified.example", defaultRouterRepo)
	client.setVerifiedState(&GroundTruth{EnclaveHost: "verified.example"})

	client.SetExpectedRTMR3("sealed")

	assert.Nil(t, client.GroundTruth())
	assert.EqualError(t, client.validateBundleDomain("other.example"),
		`verifyBundle: domain "other.example" does not match verified enclave "verified.example"`)
}

func TestBundleDomainAllowsInitialDiscovery(t *testing.T) {
	client := NewSecureClient("configured.example", defaultRouterRepo)

	assert.NoError(t, client.validateBundleDomain("discovered.example"))
}

func TestNewDefaultSecureClient(t *testing.T) {
	client, err := NewDefaultClient()
	assert.NoError(t, err)
	assert.NotNil(t, client)

	enclave := client.Enclave()
	assert.NotEmpty(t, enclave)

	_, err = client.Verify()
	assert.NoError(t, err)
}

func TestClientFetchRouters(t *testing.T) {
	routers, err := fetchRouters()
	assert.NoError(t, err)
	assert.Greater(t, len(routers), 0)
	assert.True(t, strings.HasSuffix(routers[0], ".tinfoil.sh"))
}

func TestClientDefaultClient(t *testing.T) {
	defaultClient := newFallbackClient()
	enclave := defaultClient.Enclave()
	assert.NotEmpty(t, enclave)

	_, err := defaultClient.Verify()
	assert.NoError(t, err)
}

func TestVerifyFromBundle(t *testing.T) {
	bundle, err := attestation.FetchBundle()
	assert.NoError(t, err)
	assert.NotNil(t, bundle)
	assert.NotEmpty(t, bundle.Domain)
	assert.NotEmpty(t, bundle.Digest)
	assert.NotNil(t, bundle.EnclaveAttestationReport)
	assert.NotEmpty(t, bundle.VCEK)
	assert.NotEmpty(t, bundle.SigstoreBundle)

	client := NewSecureClient(bundle.Domain, defaultRouterRepo)
	groundTruth, err := client.VerifyFromBundle(bundle)
	assert.NoError(t, err)
	assert.NotNil(t, groundTruth)
	assert.NotEmpty(t, groundTruth.TLSPublicKey)
	assert.NotEmpty(t, groundTruth.HPKEPublicKey)
	assert.Equal(t, bundle.Digest, groundTruth.Digest)
}

// testRegister returns a well-formed 48-byte hex register filled with one digit.
func testRegister(digit byte) string {
	return strings.Repeat(string(digit), 96)
}

func TestVerifyRejectsPinnedMeasurementWithBundle(t *testing.T) {
	codeMeasurement := &attestation.Measurement{
		Type:      attestation.SnpTdxMultiPlatformV1,
		Registers: []string{testRegister('a'), testRegister('b'), testRegister('c')},
	}
	client, err := NewPinnedSecureClient("enclave.test", codeMeasurement, nil)
	assert.NoError(t, err)
	client.SetAttestationBundleURL("https://atc.example")

	_, err = client.Verify()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot combine")
}

func TestNewPinnedSecureClientCopiesInputs(t *testing.T) {
	codeMeasurement := &attestation.Measurement{
		Type:      attestation.SevGuestV2,
		Registers: []string{strings.ToUpper(testRegister('a'))},
	}
	hardware := &attestation.HardwareMeasurement{ID: "platform@digest", MRTD: testRegister('b'), RTMR0: testRegister('c')}

	client, err := NewPinnedSecureClient("enclave.test", codeMeasurement, []*attestation.HardwareMeasurement{hardware})
	assert.NoError(t, err)

	// Registers are normalized to lowercase for comparison.
	assert.Equal(t, []string{testRegister('a')}, client.codeMeasurement.Registers)

	// Mutating the caller's values after construction must not change the pin.
	codeMeasurement.Registers[0] = testRegister('f')
	codeMeasurement.Type = attestation.TdxGuestV2
	hardware.MRTD = testRegister('f')
	assert.Equal(t, attestation.SevGuestV2, client.codeMeasurement.Type)
	assert.Equal(t, []string{testRegister('a')}, client.codeMeasurement.Registers)
	assert.Equal(t, testRegister('b'), client.hardwareMeasurements[0].MRTD)
}

func TestNewPinnedSecureClientRejectsMalformedPins(t *testing.T) {
	valid := testRegister('a')
	tests := map[string]*attestation.Measurement{
		"nil":                nil,
		"missing type":       {Registers: []string{valid}},
		"unsupported type":   {Type: attestation.HardwareMeasurementsV1, Registers: []string{valid}},
		"no registers":       {Type: attestation.SevGuestV2, Registers: nil},
		"too many registers": {Type: attestation.SevGuestV2, Registers: []string{valid, valid}},
		"too few TDX":        {Type: attestation.TdxGuestV2, Registers: []string{valid, valid, valid, valid}},
		"too few MP":         {Type: attestation.SnpTdxMultiPlatformV1, Registers: []string{valid, valid}},
		"short register":     {Type: attestation.SevGuestV2, Registers: []string{"abc"}},
		"non-hex register":   {Type: attestation.SevGuestV2, Registers: []string{strings.Repeat("z", 96)}},
	}
	for name, measurement := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewPinnedSecureClient("enclave.test", measurement, nil)
			assert.Error(t, err)
		})
	}

	for name, hardware := range map[string][]*attestation.HardwareMeasurement{
		"nil entry":    {nil},
		"missing ID":   {{MRTD: valid, RTMR0: valid}},
		"short MRTD":   {{ID: "p", MRTD: "abc", RTMR0: valid}},
		"non-hex RTMR": {{ID: "p", MRTD: valid, RTMR0: strings.Repeat("z", 96)}},
	} {
		t.Run("hardware "+name, func(t *testing.T) {
			_, err := NewPinnedSecureClient("enclave.test", &attestation.Measurement{Type: attestation.SevGuestV2, Registers: []string{valid}}, hardware)
			assert.Error(t, err)
		})
	}
}

func TestPinnedTDXMeasurementFixesRTMR3Expectation(t *testing.T) {
	sealed := testRegister('e')
	client, err := NewPinnedSecureClient("enclave.test", &attestation.Measurement{
		Type:      attestation.TdxGuestV2,
		Registers: []string{testRegister('a'), testRegister('b'), testRegister('c'), testRegister('d'), sealed},
	}, nil)
	assert.NoError(t, err)
	assert.Equal(t, sealed, client.rtmr3Expectation())

	// The pin is the authority on RTMR3, so a later expectation cannot loosen it.
	client.SetExpectedRTMR3("")
	assert.Equal(t, sealed, client.rtmr3Expectation())

	sev, err := NewPinnedSecureClient("enclave.test", &attestation.Measurement{
		Type:      attestation.SevGuestV2,
		Registers: []string{testRegister('a')},
	}, nil)
	assert.NoError(t, err)
	assert.Equal(t, attestation.RTMR3_ZERO, sev.rtmr3Expectation())
}

func TestNewPinnedSecureClientJSON(t *testing.T) {
	measurementJSON := `{"type":"https://tinfoil.sh/predicate/sev-snp-guest/v2","registers":["` + testRegister('a') + `"]}`
	hardwareJSON := `[{"ID":"platform@digest","MRTD":"` + testRegister('b') + `","RTMR0":"` + testRegister('c') + `"}]`

	client, err := NewPinnedSecureClientJSON("enclave.test", measurementJSON, hardwareJSON)
	assert.NoError(t, err)
	assert.Equal(t, "enclave.test", client.Enclave())
	assert.Equal(t, pinnedNoRepo, client.Repo())
	assert.Equal(t, attestation.SevGuestV2, client.codeMeasurement.Type)
	assert.Equal(t, []string{testRegister('a')}, client.codeMeasurement.Registers)
	assert.Len(t, client.hardwareMeasurements, 1)
	assert.Equal(t, testRegister('b'), client.hardwareMeasurements[0].MRTD)

	client, err = NewPinnedSecureClientJSON("enclave.test", measurementJSON, "")
	assert.NoError(t, err)
	assert.Empty(t, client.hardwareMeasurements)

	for name, input := range map[string]string{
		"invalid JSON":    `{`,
		"null":            `null`,
		"missing type":    `{"registers":["` + testRegister('a') + `"]}`,
		"empty registers": `{"type":"https://tinfoil.sh/predicate/sev-snp-guest/v2","registers":[]}`,
		"short register":  `{"type":"https://tinfoil.sh/predicate/sev-snp-guest/v2","registers":["abc"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewPinnedSecureClientJSON("enclave.test", input, "")
			assert.Error(t, err)
		})
	}

	for name, input := range map[string]string{
		"not json":   `not json`,
		"null entry": `[null]`,
	} {
		t.Run("hardware "+name, func(t *testing.T) {
			_, err := NewPinnedSecureClientJSON("enclave.test", measurementJSON, input)
			assert.Error(t, err)
		})
	}
}

func TestVerifyFromBundleJSON(t *testing.T) {
	bundle, err := attestation.FetchBundle()
	assert.NoError(t, err)

	bundleJSON, err := json.Marshal(bundle)
	assert.NoError(t, err)

	groundTruthJSON, err := VerifyFromBundleJSON(bundleJSON, defaultRouterRepo, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, groundTruthJSON)

	var groundTruth GroundTruth
	err = json.Unmarshal([]byte(groundTruthJSON), &groundTruth)
	assert.NoError(t, err)
	assert.NotEmpty(t, groundTruth.TLSPublicKey)
	assert.NotEmpty(t, groundTruth.HPKEPublicKey)
	assert.Equal(t, bundle.Digest, groundTruth.Digest)
}

func TestFetchAndVerifyJSON(t *testing.T) {
	groundTruthJSON, err := FetchAndVerifyJSON(defaultRouterRepo, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, groundTruthJSON)

	var groundTruth GroundTruth
	err = json.Unmarshal([]byte(groundTruthJSON), &groundTruth)
	assert.NoError(t, err)
	assert.NotEmpty(t, groundTruth.EnclaveHost)
	assert.True(t, strings.HasSuffix(groundTruth.EnclaveHost, ".tinfoil.sh"))
	assert.NotEmpty(t, groundTruth.TLSPublicKey)
	assert.NotEmpty(t, groundTruth.HPKEPublicKey)
	assert.NotEmpty(t, groundTruth.Digest)
}

func TestFetchAndVerifyFromURLJSON(t *testing.T) {
	groundTruthJSON, err := FetchAndVerifyFromURLJSON("", defaultRouterRepo, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, groundTruthJSON)

	var groundTruth GroundTruth
	err = json.Unmarshal([]byte(groundTruthJSON), &groundTruth)
	assert.NoError(t, err)
	assert.NotEmpty(t, groundTruth.TLSPublicKey)
	assert.NotEmpty(t, groundTruth.HPKEPublicKey)
	assert.NotEmpty(t, groundTruth.Digest)
}
