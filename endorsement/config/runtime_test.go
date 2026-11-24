package config_test

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

func TestRuntimeFromConfigBoundsItsInput(t *testing.T) {
	oversized := []byte(strings.Repeat("x", configendorsement.MaxConfigSize+1))
	_, err := configendorsement.RuntimeFromConfig(oversized)
	require.ErrorContains(t, err, "exceeds")
}

func TestRuntimeFromPin(t *testing.T) {
	digest := strings.Repeat("ab", sha256.Size)
	ref, err := configendorsement.RuntimeFromPin("0.15.0@sha256:" + digest)
	require.NoError(t, err)
	require.Equal(t, configendorsement.RuntimeReference{Repo: configendorsement.RuntimeRepo, Tag: "v0.15.0", Digest: digest}, ref)
	for name, pin := range map[string]string{
		"empty":           "",
		"unpinned":        "0.15.0",
		"partial version": "0.15@sha256:" + digest,
		"short digest":    "0.15.0@sha256:" + digest[2:],
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configendorsement.RuntimeFromPin(pin)
			require.Error(t, err)
		})
	}
}

func TestNewDeploymentStatementForRuntime(t *testing.T) {
	digest := strings.Repeat("ab", sha256.Size)
	runtime := configendorsement.RuntimeReference{Repo: configendorsement.RuntimeRepo, Tag: "v0.15.0", Digest: digest}
	other := runtime
	other.Tag = "v0.16.0"

	s, err := configendorsement.NewDeploymentStatementForRuntime(testName, configendorsement.PublicRegistryID, testConfig, runtime)
	require.NoError(t, err)
	require.Equal(t, configendorsement.PredicateTypeV2, s.PredicateType)
	require.Equal(t, &runtime, s.Predicate.Runtime)

	pinned := []byte(`{"cvm-version":"0.15.0@sha256:` + digest + `"}`)
	_, err = configendorsement.NewDeploymentStatementForRuntime(testName, configendorsement.PublicRegistryID, pinned, runtime)
	require.NoError(t, err)
	_, err = configendorsement.NewDeploymentStatementForRuntime(testName, configendorsement.PublicRegistryID, pinned, other)
	require.ErrorContains(t, err, "does not match the one the config pins")

	_, err = configendorsement.NewDeploymentStatementForRuntime(testName, configendorsement.PublicRegistryID, testConfig, configendorsement.RuntimeReference{})
	require.Error(t, err)
}
