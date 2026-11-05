package enclave

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func TestNewChecksConfig(t *testing.T) {
	_, err := New(Config{Host: "enclave.example", Repo: "not a reference"})
	require.ErrorIs(t, err, errs.ErrConfiguration)
	_, err = New(Config{Host: "enclave.example"})
	require.NoError(t, err)
	authorizer, err := verify.NewVerifier(verify.WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return nil }))
	require.NoError(t, err)
	_, err = New(Config{Host: "enclave.example", Repo: "org/repo", Verifier: authorizer})
	require.ErrorIs(t, err, errs.ErrConfiguration, "a config authorizer can't verify a repository pin")

	v, err := verify.NewVerifier(verify.WithFreshnessMaxAge(time.Hour))
	require.NoError(t, err)
	s, err := New(Config{Host: "enclave.example", Relay: "relay.example", Repo: "org/repo", Verifier: v})
	require.NoError(t, err)
	require.Same(t, v, s.verifier, "enclaves share the caller's verifier")
	require.Equal(t, "relay.example", s.relay)
}

func TestConfigRegistryIDRequiresRegistryEvidence(t *testing.T) {
	const registryID = "https://registry.tinfoil.sh/scopes/9c4a7f21e0b836d56a13c8fe42d907ab"
	verifier, err := verify.NewVerifier(verify.WithConfigRegistryIDs(registryID))
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
		enclave, err := New(config)
		require.NoError(t, err)
		_, err = enclave.Verifier().VerifyV3(raw, nonce, "")
		require.ErrorContains(t, err, "configured trust requires "+collateral.FormatV3)
	}
}

func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	client, err := New(Config{Host: os.Getenv(enclaveEnvVar), Repo: os.Getenv(repoEnvVar)})
	require.NoError(t, err)
	_, err = client.Verify()
	assert.NoError(t, err)
}
