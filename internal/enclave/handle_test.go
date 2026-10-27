package enclave

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

func TestNewHandleChecksConfig(t *testing.T) {
	var config *ConfigurationError
	_, err := NewHandle(Config{Host: "enclave.example", Repo: "not a reference"})
	require.ErrorAs(t, err, &config)
	_, err = NewHandle(Config{Host: "enclave.example"})
	require.ErrorAs(t, err, &config, "the default policy requires a repository pin")
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

func TestLiveVerify(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	client, err := NewHandle(Config{Host: os.Getenv(enclaveEnvVar), Repo: os.Getenv(repoEnvVar)})
	require.NoError(t, err)
	_, err = client.Reverify(t.Context())
	assert.NoError(t, err)
}

func TestLiveDiscoverRouter(t *testing.T) {
	testutil.RequireLive(t)
	client, err := DiscoverRouter(t.Context(), nil)
	require.NoError(t, err)
	assert.NotEmpty(t, client.Enclave())
	_, err = client.Reverify(t.Context())
	assert.NoError(t, err)
}

func TestLiveClientFetchRouters(t *testing.T) {
	testutil.RequireLive(t)
	routers, err := fetchRouters(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, routers)
	assert.True(t, strings.HasSuffix(routers[0], ".tinfoil.sh"))
}

func TestLiveClientFallbackEnclave(t *testing.T) {
	testutil.RequireLive(t)
	defaultClient, err := NewHandle(Config{Host: "inference.tinfoil.sh", Repo: defaultRouterRepo})
	require.NoError(t, err)
	_, err = defaultClient.Reverify(t.Context())
	assert.NoError(t, err)
}
