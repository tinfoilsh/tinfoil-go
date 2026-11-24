package config_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

// A config is read only as JSON, for its cvm-version member alone. Neither
// the version it pins nor the spelling of the JSON decides the outcome; YAML
// is refused.
func TestRuntimeFromConfigReadsOnlyJSON(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	json := func(version string) string {
		return `{"containers":[],"cpus":2,"cvm-version":"` + version + `@sha256:` + digest + `","shim":{"upstream-port":8080}}`
	}
	yaml := func(version string) string {
		return "cvm-version: " + version + "@sha256:" + digest + "\ncpus: 2\n"
	}
	config := json("0.15.5-rc.1")
	replace := func(old, new string) string {
		require.Contains(t, config, old)
		return strings.Replace(config, old, new, 1)
	}
	for name, tt := range map[string]struct {
		config  string
		wantTag string
	}{
		"release candidate":     {config, "v0.15.5-rc.1"},
		"v prefix":              {json("v0.15.5-rc.1"), "v0.15.5-rc.1"},
		"build metadata":        {json("0.15.5-rc.1+gpu"), "v0.15.5-rc.1+gpu"},
		"earlier version":       {json("0.15.4"), "v0.15.4"},
		"later version":         {json("0.16.0"), "v0.16.0"},
		"whitespace":            {replace(`"cpus":2`, `"cpus": 2`) + "\n", "v0.15.5-rc.1"},
		"members in any order":  {replace(`"containers":[],"cpus":2,`, `"cpus":2,"containers":[],`), "v0.15.5-rc.1"},
		"other member is null":  {replace(`"cpus":2`, `"cpus":null`), "v0.15.5-rc.1"},
		"other member fraction": {replace(`"cpus":2`, `"cpus":2.5`), "v0.15.5-rc.1"},
	} {
		t.Run(name, func(t *testing.T) {
			ref, err := configendorsement.RuntimeFromConfig([]byte(tt.config))
			require.NoError(t, err)
			require.Equal(t, configendorsement.RuntimeReference{Repo: configendorsement.RuntimeRepo, Tag: tt.wantTag, Digest: digest}, ref)
		})
	}

	const notJSON = "not a JSON config"
	for name, tt := range map[string]struct{ config, wantError string }{
		"YAML":                     {yaml("0.15.5-rc.1"), notJSON},
		"YAML, earlier version":    {yaml("0.15.4"), notJSON},
		"no cvm-version":           {replace(`"cvm-version"`, `"cvm-versions"`), notJSON},
		"cvm-version not a string": {`{"cvm-version":2}`, notJSON},
		"cvm-version null":         {`{"cvm-version":null}`, notJSON},
		"not an object":            {`["0.15.5-rc.1@sha256:` + digest + `"]`, notJSON},
		"repeated member":          {replace(`"cpus":2,`, `"cpus":2,"cpus":2,`), "duplicate"},
		"repeated cvm-version":     {replace(`"shim"`, `"cvm-version":"x","shim"`), "duplicate"},
		"second value":             {config + config, notJSON},
		"unpinned version":         {replace("@sha256:"+digest, ""), "must pin"},
		"partial version":          {json("0.15"), "full semantic version"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configendorsement.RuntimeFromConfig([]byte(tt.config))
			require.ErrorContains(t, err, tt.wantError)
		})
	}
}

// A pin is read whatever version it names, for callers that take it from a
// config that RuntimeFromConfig does not read.
// A config over the size limit is refused before it is parsed, also when a
// statement is built from it.
func TestOversizedConfigIsRefusedUnparsed(t *testing.T) {
	// Not JSON: a parser would report a syntax error instead of the size.
	oversized := []byte(strings.Repeat("x", configendorsement.MaxConfigSize+1))
	_, err := configendorsement.RuntimeFromConfig(oversized)
	require.ErrorContains(t, err, "larger than")
	_, err = configendorsement.NewDeploymentStatement("project/app", configendorsement.PublicRegistryID, oversized)
	require.ErrorContains(t, err, "larger than")
}

func TestRuntimeFromPin(t *testing.T) {
	digest := strings.Repeat("ab", sha256.Size)
	for version, wantTag := range map[string]string{
		"0.15.4":          "v0.15.4",
		"v0.15.4":         "v0.15.4",
		"0.15.3-rc.1+gpu": "v0.15.3-rc.1+gpu",
		"0.15.5-rc.1":     "v0.15.5-rc.1",
	} {
		ref, err := configendorsement.RuntimeFromPin(version + "@sha256:" + digest)
		require.NoError(t, err, version)
		require.Equal(t, configendorsement.RuntimeReference{Repo: configendorsement.RuntimeRepo, Tag: wantTag, Digest: digest}, ref)
	}
	for name, tt := range map[string]struct{ pin, wantError string }{
		"version alone":    {"0.15.4", "must pin"},
		"empty":            {"", "must pin"},
		"partial version":  {"0.15@sha256:" + digest, "full semantic version"},
		"no version":       {"@sha256:" + digest, "full semantic version"},
		"path in metadata": {"0.15.4+mini/other@sha256:" + digest, "full semantic version"},
		"uppercase digest": {"0.15.4@sha256:" + strings.ToUpper(digest), "runtime digest"},
		"short digest":     {"0.15.4@sha256:" + digest[2:], "runtime digest"},
		"second digest":    {"0.15.4@sha256:" + digest + "@sha256:" + digest, "runtime digest"},
		"other algorithm":  {"0.15.4@sha512:" + digest, "must pin"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configendorsement.RuntimeFromPin(tt.pin)
			require.ErrorContains(t, err, tt.wantError)
		})
	}
}

// A caller that reads the cvm-version of a YAML config itself gets a
// statement for the exact YAML bytes and the runtime that it supplies.
func TestDeploymentStatementForACallerSuppliedRuntime(t *testing.T) {
	pin := "0.15.4@sha256:" + strings.Repeat("ab", sha256.Size)
	config := []byte("cvm-version: " + pin + "\ncpus: 2\n")
	_, err := configendorsement.NewDeploymentStatement(testName, configendorsement.PublicRegistryID, config)
	require.ErrorContains(t, err, "not a JSON config")

	runtime, err := configendorsement.RuntimeFromPin(pin)
	require.NoError(t, err)
	s, err := configendorsement.NewDeploymentStatementForRuntime(testName, configendorsement.PublicRegistryID, config, runtime)
	require.NoError(t, err)
	digest := sha256.Sum256(config)
	require.Equal(t, &configendorsement.Statement{
		Type:          configendorsement.StatementType,
		Subject:       []configendorsement.Subject{{Name: testName, Digest: map[string]string{"sha256": hex.EncodeToString(digest[:])}}},
		PredicateType: configendorsement.PredicateTypeV2,
		Predicate:     configendorsement.Predicate{RegistryID: configendorsement.PublicRegistryID, Runtime: &runtime},
	}, s)
	_, err = s.TimestampInput()
	require.NoError(t, err, "the statement is ready for its timestamp")

	otherRepo := runtime
	otherRepo.Repo = "other/runtime"
	for name, tt := range map[string]struct {
		registryID string
		config     []byte
		runtime    configendorsement.RuntimeReference
		wantError  string
	}{
		"no runtime":         {configendorsement.PublicRegistryID, config, configendorsement.RuntimeReference{}, "runtime repository"},
		"another repository": {configendorsement.PublicRegistryID, config, otherRepo, "runtime repository"},
		"no registry ID":     {"", config, runtime, "registry ID"},
		"no config":          {configendorsement.PublicRegistryID, nil, runtime, "config size"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configendorsement.NewDeploymentStatementForRuntime(testName, tt.registryID, tt.config, tt.runtime)
			require.ErrorContains(t, err, tt.wantError)
		})
	}
}

// A config this package can read has to agree with the runtime a caller
// supplies.
func TestCallerSuppliedRuntimeMustMatchAReadableConfig(t *testing.T) {
	digest := strings.Repeat("ab", sha256.Size)
	config := []byte(`{"cvm-version":"0.15.5-rc.1@sha256:` + digest + `"}`)
	stated, err := configendorsement.RuntimeFromConfig(config)
	require.NoError(t, err)
	_, err = configendorsement.NewDeploymentStatementForRuntime(testName, configendorsement.PublicRegistryID, config, stated)
	require.NoError(t, err)
	other := stated
	other.Tag = "v0.16.0"
	_, err = configendorsement.NewDeploymentStatementForRuntime(testName, configendorsement.PublicRegistryID, config, other)
	require.ErrorContains(t, err, "does not match the one the config pins")
}
