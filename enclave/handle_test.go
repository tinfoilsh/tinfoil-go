package enclave

import (
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestClientConfigAuthorizerSurvivesDerivedHandles(t *testing.T) {
	rejected := errors.New("config rejected")
	opts := &Options{ConfigAuthorizer: func(collateral.ConfigEndorsement) error { return rejected }}
	_, err := NewHandle("", "", opts)
	require.ErrorContains(t, err, "requires an enclave")
	_, err = NewDefaultHandle(opts)
	require.ErrorContains(t, err, "requires an explicit enclave")
	_, err = NewHandle("enclave.example", "org/project", opts)
	require.ErrorContains(t, err, "requires an empty repository pin")
	client, err := NewHandle("enclave.example", "", opts)
	require.NoError(t, err)
	opts.ConfigAuthorizer = nil
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3, Collateral: []collateral.Entry{{
		ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: []byte(`{"config_base64":"Y29uZmln"}`),
	}}}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = client.ForEnclave("other.example").ViaRelay("relay.example").verifier.VerifyV3(raw, nonce, "")
	require.ErrorIs(t, err, rejected)
}

func TestClientEmbeddedConfigRetainsOtherEndorsements(t *testing.T) {
	config := []byte("cvm-version: 0.15.0@sha256:" + strings.Repeat("ab", sha256.Size) + "\n")
	opts := &Options{EmbeddedConfig: &verify.EmbeddedConfig{Bytes: config}}
	_, err := NewHandle("", "", opts)
	require.ErrorContains(t, err, "caller-authorized config requires an enclave")
	_, err = NewDefaultHandle(opts)
	require.ErrorContains(t, err, "caller-authorized config requires an explicit enclave")
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
	require.NoError(t, err)
	_, err = NewHandle("enclave.example", "", &Options{EmbeddedConfig: &verify.EmbeddedConfig{}})
	require.Error(t, err)
	config[0] = 'c'
	_, err = NewHandle("enclave.example", "invalid", &Options{EmbeddedConfig: &verify.EmbeddedConfig{Bytes: config}})
	var configError *ConfigurationError
	require.ErrorAs(t, err, &configError)
}

func TestClientOptionsCopyPinnedRegisters(t *testing.T) {
	register := measurement.Register{0xab}
	pinned := register
	opts := Options{PinnedRegisters: measurement.ExpectedTDX{RTMR3: &pinned}, FreshnessMaxAge: time.Hour}
	first, err := NewHandle("enclave.example", "org/repo", &opts)
	require.NoError(t, err)
	second, err := NewHandle("enclave.example", "org/repo", &opts)
	require.NoError(t, err)

	// Mutating the caller's options and registers after construction must
	// not reach either client. That the accessor also copies on the way out is
	// the verifier package's contract, covered by its own tests.
	opts.FreshnessMaxAge = time.Minute
	pinned[0] = 0xcd
	assert.Equal(t, register, *first.verifier.PinnedRegisters().(measurement.ExpectedTDX).RTMR3)
	assert.Equal(t, register, *second.verifier.PinnedRegisters().(measurement.ExpectedTDX).RTMR3)
	assert.Equal(t, time.Hour, second.verifier.FreshnessMaxAge())
}

func TestConfigAuthorityPinsRequireRegistryEvidence(t *testing.T) {
	opts := &Options{ConfigPins: verify.ConfigPins{Namespace: "acme"}}
	handle, err := NewHandle("enclave.example", "", opts)
	require.NoError(t, err)
	opts.ConfigPins = verify.ConfigPins{}
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV2}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("quote"), nil
	})
	require.NoError(t, err)
	for _, h := range []*Handle{handle, handle.ForEnclave("other.example"), handle.ViaRelay("relay.example")} {
		_, err := h.verifier.VerifyV3(raw, nonce, "")
		require.ErrorContains(t, err, "configured trust requires "+collateral.FormatV3)
	}
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
