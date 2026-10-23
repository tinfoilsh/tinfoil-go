package enclave

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func TestNewHandleChecksConfig(t *testing.T) {
	var config *ConfigurationError
	_, err := NewHandle(Config{Host: "enclave.example", Repo: "not a reference"})
	require.ErrorAs(t, err, &config)
	_, err = NewHandle(Config{Host: "enclave.example"})
	require.NoError(t, err)
	authorizer, err := verify.NewVerifier(verify.WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return nil }))
	require.NoError(t, err)
	_, err = NewHandle(Config{Host: "enclave.example", Repo: "org/repo", Verifier: authorizer})
	require.ErrorAs(t, err, &config, "a config authorizer can't verify a repository pin")

	v, err := verify.NewVerifier(verify.WithFreshnessMaxAge(time.Hour))
	require.NoError(t, err)
	s, err := NewHandle(Config{Host: "enclave.example", Relay: "relay.example", Repo: "org/repo", Verifier: v})
	require.NoError(t, err)
	require.Same(t, v, s.verifier, "handles share the caller's verifier")
	require.Equal(t, "relay.example", s.relay)
	require.Nil(t, s.Current(), "a handle does no I/O before first use")
}

func TestConfigAuthorityPinsRequireRegistryEvidence(t *testing.T) {
	verifier, err := verify.NewVerifier(verify.WithConfigPins(verify.ConfigPins{Namespace: "acme"}))
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV2}, func([64]byte) (string, []byte, error) {
		return document.SEVSNPReportV1Format, []byte("quote"), nil
	})
	require.NoError(t, err)
	for _, config := range []Config{
		{Host: "enclave.example", Verifier: verifier},
		{Host: "other.example", Relay: "relay.example", Verifier: verifier},
	} {
		handle, err := NewHandle(config)
		require.NoError(t, err)
		_, err = handle.Verifier().VerifyV3(raw, nonce, "")
		require.ErrorContains(t, err, "configured trust requires "+collateral.FormatV3)
	}
}

func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	client, err := NewHandle(Config{Host: os.Getenv(enclaveEnvVar), Repo: os.Getenv(repoEnvVar)})
	require.NoError(t, err)
	_, err = client.Reverify(t.Context())
	assert.NoError(t, err)
}
