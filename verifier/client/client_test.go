package client

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

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
