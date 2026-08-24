package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestVerifyFromBundleRejectsConfiguredDomainMismatch(t *testing.T) {
	client := NewSecureClient("configured.example", defaultRouterRepo)
	client.setVerifiedState(&GroundTruth{EnclaveHost: "configured.example"})

	_, err := client.VerifyFromBundle(&attestation.Bundle{Domain: "other.example"})

	assert.EqualError(t, err, `verifyBundle: domain "other.example" does not match configured enclave "configured.example"`)
	assert.Equal(t, "configured.example", client.Enclave())
	assert.Equal(t, "configured.example", client.GroundTruth().EnclaveHost)
}

func TestBundleDomainRejectsInitialConfiguredMismatch(t *testing.T) {
	client := NewSecureClient("configured.example", defaultRouterRepo)

	assert.EqualError(t, client.validateBundleDomain("discovered.example"),
		`verifyBundle: domain "discovered.example" does not match configured enclave "configured.example"`)
}

func TestBundleDomainAllowsAutomaticRouterRotation(t *testing.T) {
	client := NewSecureClient("", defaultRouterRepo)
	client.setVerifiedState(&GroundTruth{EnclaveHost: "old-router.example"})

	assert.NoError(t, client.validateBundleDomain("new-router.example"))
}

func TestAutomaticBundleRecoveryDoesNotPinDiscoveredRouter(t *testing.T) {
	client := NewSecureClient("", defaultRouterRepo)
	client.setVerifiedState(&GroundTruth{EnclaveHost: "old-router.example"})

	enclaveURL, repo := client.bundleRequestParameters()

	assert.Empty(t, enclaveURL)
	assert.Empty(t, repo)
}

func TestConfiguredBundleRecoveryKeepsCallerConstraints(t *testing.T) {
	client := NewSecureClient("configured.example", "owner/custom-router")
	client.setVerifiedState(&GroundTruth{EnclaveHost: "configured.example"})

	enclaveURL, repo := client.bundleRequestParameters()

	assert.Equal(t, "https://configured.example", enclaveURL)
	assert.Equal(t, "owner/custom-router", repo)
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

func TestNewDefaultClientFailsClosedWhenATCReturnsNoRouters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	originalRouterURL := defaultRouterURL
	defaultRouterURL = server.URL
	t.Cleanup(func() { defaultRouterURL = originalRouterURL })

	secureClient, err := NewDefaultClient()

	assert.Nil(t, secureClient)
	assert.EqualError(t, err, "ATC returned no routers")
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

func TestVerifyRejectsPinnedMeasurementWithBundle(t *testing.T) {
	codeMeasurement := &attestation.Measurement{
		Type:      attestation.SnpTdxMultiPlatformV1,
		Registers: []string{"a", "b"},
	}
	client := NewPinnedSecureClient("enclave.test", codeMeasurement, nil)
	client.SetAttestationBundleURL("https://atc.example")

	_, err := client.Verify()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot combine")
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
