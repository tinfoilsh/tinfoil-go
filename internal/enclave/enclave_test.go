package enclave

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func TestNewChecksConfig(t *testing.T) {
	var config *ConfigurationError
	_, err := New(Config{Host: "enclave.example", Repo: "not a reference"})
	require.ErrorAs(t, err, &config)
	_, err = New(Config{Host: "enclave.example"})
	require.ErrorAs(t, err, &config, "the default policy requires a repository pin")
	authorizer, err := verify.NewVerifier(verify.WithConfigAuthorizer(func(collateral.ConfigEndorsement) error { return nil }))
	require.NoError(t, err)
	_, err = New(Config{Host: "enclave.example", Repo: "org/repo", Verifier: authorizer})
	require.ErrorAs(t, err, &config, "a config authorizer can't verify a repository pin")

	v, err := verify.NewVerifier(verify.WithFreshnessMaxAge(time.Hour))
	require.NoError(t, err)
	s, err := New(Config{Host: "enclave.example", Relay: "relay.example", Repo: "org/repo", Verifier: v})
	require.NoError(t, err)
	require.Same(t, v, s.verifier, "enclaves share the caller's verifier")
	require.Equal(t, "relay.example", s.relay)
}

func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	client, err := New(Config{Host: os.Getenv(enclaveEnvVar), Repo: os.Getenv(repoEnvVar)})
	require.NoError(t, err)
	_, err = client.Verify()
	assert.NoError(t, err)
}
