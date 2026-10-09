package enclave

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestClientEmbeddedConfigRetainsOtherEndorsements(t *testing.T) {
	config := []byte("cvm-version: 0.15.0@sha256:" + strings.Repeat("ab", sha256.Size) + "\n")
	opts := &Options{EmbeddedConfig: &verify.EmbeddedConfig{Bytes: config}}
	client, err := NewHandle("enclave.example", "", opts)
	require.NoError(t, err)
	config[0] = '!'
	opts.EmbeddedConfig = nil

	nonce := make([]byte, document.NonceSize)
	for _, format := range []string{collateral.FormatV3, collateral.FormatV2} {
		raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: format}, func([64]byte) (string, []byte, error) {
			return document.SEVSNPReportV1Format, []byte("unauthenticated quote"), nil
		})
		require.NoError(t, err)
		_, err = client.ForEnclave("other.example").verifier.VerifyV3(raw, nonce, "")
		if format == collateral.FormatV3 {
			require.ErrorIs(t, err, collateral.ErrNotFound)
			require.ErrorContains(t, err, collateral.RuntimeID)
		} else {
			require.ErrorContains(t, err, "configured trust requires "+collateral.FormatV3)
		}
	}

	_, err = NewHandle("enclave.example", "", nil)
	require.Error(t, err)
	_, err = NewHandle("enclave.example", "", &Options{EmbeddedConfig: &verify.EmbeddedConfig{}})
	require.Error(t, err)
	_, err = NewHandle("enclave.example", "invalid", &Options{EmbeddedConfig: &verify.EmbeddedConfig{Bytes: config}})
	require.Error(t, err)
}

func TestClientOptionsCopyPinnedRegisters(t *testing.T) {
	register := strings.Repeat("ab", 48)
	pins := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}
	opts := Options{PinnedRegisters: pins, FreshnessMaxAge: time.Hour}
	first, err := NewHandle("enclave.example", "org/repo", &opts)
	require.NoError(t, err)
	second, err := NewHandle("enclave.example", "org/repo", &opts)
	require.NoError(t, err)

	// Mutating the caller's options and measurement after construction must
	// not reach either client. That the accessor also copies on the way out is
	// the verifier package's contract, covered by its own tests.
	opts.FreshnessMaxAge = time.Minute
	pins.Type = measurement.SevGuestV2
	pins.Registers[4] = "changed"
	assert.Equal(t, measurement.TdxGuestV2, first.verifier.PinnedRegisters().Type)
	assert.Equal(t, register, first.verifier.PinnedRegisters().Registers[4])
	assert.Equal(t, register, second.verifier.PinnedRegisters().Registers[4])
	assert.Equal(t, time.Hour, second.verifier.FreshnessMaxAge())
}

func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	enclave := os.Getenv(enclaveEnvVar)
	repo := os.Getenv(repoEnvVar)

	client, err := NewHandle(enclave, repo, nil)
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

	verified := &verify.Verification{
		CodeDigest:         "feabcd",
		CryptoMaterial:     testState(time.Time{}, "key").CryptoMaterial,
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: enclaveMeasurement,
		Config:             &verify.ConfigVerification{Source: verify.SourceEndorsement, Name: "/org/project/v1"},
		Runtime:            &verify.ArtifactVerification{Source: verify.SourceEndorsement, Digest: "runtime digest"},
		Platform:           &verify.ArtifactVerification{Source: verify.SourceEndorsement, Digest: "platform digest"},
	}
	client := &Handle{
		state: &enclaveState{Verification: verified},
	}

	encoded, err := client.VerificationJSON()
	assert.NoError(t, err)

	var decoded verify.Verification
	assert.NoError(t, json.Unmarshal([]byte(encoded), &decoded))
	assert.Equal(t, verified, &decoded)
	view := client.Verification()
	view.CodeMeasurement.Registers[0] = "changed"
	view.CryptoMaterial[0].Data = "changed"
	view.EnclaveMeasurement.Registers[0] = "changed"
	view.Config.Source = verify.SourceEmbedded
	view.Runtime.Digest = "changed"
	view.Platform.Digest = "changed"
	assert.Equal(t, &decoded, client.Verification(), "returned measurements must not alias cached verification")
}

func TestLiveNewDefaultHandle(t *testing.T) {
	testutil.RequireLive(t)
	client, err := NewDefaultHandle(nil)
	assert.NoError(t, err)
	assert.NotNil(t, client)

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
	defaultClient, err := NewHandle("inference.tinfoil.sh", defaultRouterRepo, nil)
	require.NoError(t, err)
	enclave := defaultClient.Enclave()
	assert.NotEmpty(t, enclave)

	_, err = defaultClient.Verify()
	assert.NoError(t, err)
}
