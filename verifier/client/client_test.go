package client

import (
	"encoding/json"
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

func TestClientOptionsCopyPinnedRegisters(t *testing.T) {
	register := strings.Repeat("ab", 48)
	pins := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}
	opts := VerificationOptions{PinnedRegisters: pins, FreshnessMaxAge: time.Hour}
	first, err := NewSecureClient("enclave.example", "org/repo", &opts)
	require.NoError(t, err)
	second, err := NewSecureClient("enclave.example", "org/repo", &opts)
	require.NoError(t, err)
	opts.FreshnessMaxAge = time.Minute
	pins.Type = measurement.SevGuestV2
	pins.Registers[4] = "changed"
	assert.Equal(t, measurement.TdxGuestV2, first.options.PinnedRegisters.Type)
	assert.Equal(t, register, first.options.PinnedRegisters.Registers[4])
	first.options.PinnedRegisters.Registers[4] = "changed again"
	assert.Equal(t, register, second.options.PinnedRegisters.Registers[4])
	assert.Equal(t, time.Hour, second.options.FreshnessMaxAge)
}

func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	enclave := os.Getenv(enclaveEnvVar)
	repo := os.Getenv(repoEnvVar)

	client, err := NewSecureClient(enclave, repo, nil)
	require.NoError(t, err)
	_, err = client.Verify()
	assert.NoError(t, err)
}

func TestClientVerificationJSON(t *testing.T) {
	codeMeasurement := &measurement.Measurement{
		Type:      measurement.SnpTdxMultiPlatformV1,
		Registers: []string{"a", "b"},
	}
	enclaveMeasurement := &measurement.Measurement{
		Type:      measurement.TdxGuestV2,
		Registers: []string{"a"},
	}

	verified := &VerifiedDocumentV3{
		CodeDigest:         "feabcd",
		CryptoMaterial:     testState(time.Time{}, "key").CryptoMaterial,
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: enclaveMeasurement,
	}
	client := &SecureClient{
		state: verified,
	}

	encoded, err := client.VerificationJSON()
	assert.NoError(t, err)

	var decoded VerifiedDocumentV3
	assert.NoError(t, json.Unmarshal([]byte(encoded), &decoded))
	assert.Equal(t, verified, &decoded)
	view := client.Verification()
	view.CodeMeasurement.Registers[0] = "changed"
	view.CryptoMaterial[0].Data = "changed"
	view.EnclaveMeasurement.Registers[0] = "changed"
	assert.Equal(t, &decoded, client.Verification(), "returned measurements must not alias cached verification")
}

func TestVerifierVersion(t *testing.T) {
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

func TestLiveNewDefaultSecureClient(t *testing.T) {
	testutil.RequireLive(t)
	client, err := NewDefaultClient(nil)
	require.NoError(t, err)

	enclave := client.Enclave()
	assert.NotEmpty(t, enclave)

	_, err = client.Verify()
	assert.NoError(t, err)
}

func TestLiveClientFetchRouters(t *testing.T) {
	testutil.RequireLive(t)
	routers, err := fetchRouters()
	require.NoError(t, err)
	require.NotEmpty(t, routers)
	assert.True(t, strings.HasSuffix(routers[0], ".tinfoil.sh"))
}

func TestLiveClientFallbackEnclave(t *testing.T) {
	testutil.RequireLive(t)
	defaultClient, err := NewSecureClient("inference.tinfoil.sh", defaultRouterRepo, nil)
	require.NoError(t, err)
	enclave := defaultClient.Enclave()
	assert.NotEmpty(t, enclave)

	_, err = defaultClient.Verify()
	assert.NoError(t, err)
}
