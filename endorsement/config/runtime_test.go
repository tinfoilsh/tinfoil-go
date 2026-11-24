package config_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

// A config is read only as canonical JSON that pins JSONConfigMinVersion or a
// later version. YAML is refused whatever version it pins.
func TestRuntimeFromConfigReadsOnlyJSON(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	json := func(version string) string {
		return `{"containers":[],"cpus":2,"cvm-version":"` + version + `@sha256:` + digest + `","shim":{"upstream-port":8080}}`
	}
	yaml := func(version string) string {
		return "cvm-version: " + version + "@sha256:" + digest + "\ncpus: 2\n"
	}
	for name, tt := range map[string]struct {
		config  string
		wantTag string
	}{
		"JSON at the first JSON version": {json("0.15.5-rc.1"), "v0.15.5-rc.1"},
		"JSON with a v prefix":           {json("v0.15.5-rc.1"), "v0.15.5-rc.1"},
		"JSON with build metadata":       {json("0.15.5-rc.1+gpu"), "v0.15.5-rc.1+gpu"},
		"JSON for its release":           {json("0.15.5"), "v0.15.5"},
		"JSON for a later version":       {json("0.16.0"), "v0.16.0"},
	} {
		t.Run(name, func(t *testing.T) {
			ref, err := configendorsement.RuntimeFromConfig([]byte(tt.config))
			require.NoError(t, err)
			require.Equal(t, configendorsement.RuntimeReference{Repo: configendorsement.RuntimeRepo, Tag: tt.wantTag, Digest: digest}, ref)
		})
	}

	canonical := json("0.15.5-rc.1")
	replace := func(old, new string) string {
		require.Contains(t, canonical, old)
		return strings.Replace(canonical, old, new, 1)
	}
	const notJSON = "not a JSON config"
	beforeJSON := "pins cvm-version " + configendorsement.JSONConfigMinVersion + " or later"
	for name, tt := range map[string]struct{ config, wantError string }{
		"YAML at the first JSON version": {yaml("0.15.5-rc.1"), notJSON},
		"YAML with build metadata":       {yaml("0.15.5-rc.1+gpu"), notJSON},
		"YAML for a later version":       {yaml("1.0.0"), notJSON},
		"YAML before the JSON version":   {yaml("0.15.5-rc.0"), notJSON},
		"YAML for an earlier release":    {yaml("0.15.4"), notJSON},
		"JSON before the JSON version":   {json("0.15.5-rc.0"), beforeJSON},
		"JSON for an earlier release":    {json("0.15.4"), beforeJSON},
		"no cvm-version":                 {replace(`"cvm-version"`, `"cvm-versions"`), notJSON},
		"cvm-version not a string":       {`{"cvm-version":2}`, notJSON},
		"not an object":                  {`["0.15.5-rc.1@sha256:` + digest + `"]`, notJSON},
		"whitespace":                     {replace(`"cpus":2`, `"cpus": 2`), "canonical form"},
		"trailing newline":               {canonical + "\n", "canonical form"},
		"members out of order":           {replace(`"containers":[],"cpus":2,`, `"cpus":2,"containers":[],`), "canonical form"},
		"escaped character":              {replace(`"cpus"`, `"`+"\\"+`u0063pus"`), "canonical form"},
		"null":                           {replace(`"cpus":2`, `"cpus":null`), "null is not allowed"},
		"fraction":                       {replace(`"cpus":2`, `"cpus":2.5`), "not an integer"},
		"exponent":                       {replace(`"cpus":2`, `"cpus":2e0`), "not an integer"},
		"integer too large":              {replace(`"cpus":2`, `"cpus":9007199254740992`), "not an integer"},
		"repeated member":                {replace(`"cpus":2,`, `"cpus":2,"cpus":2,`), ""},
		"second value":                   {canonical + canonical, ""},
		"unpinned version":               {replace("@sha256:"+digest, ""), "must pin"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configendorsement.RuntimeFromConfig([]byte(tt.config))
			require.ErrorContains(t, err, tt.wantError)
		})
	}
}

// A pin is read whatever version it names, for callers that take it from a
// config that RuntimeFromConfig does not read.
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
// supplies, and a JSON fault is reported as such.
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

	_, err = configendorsement.RuntimeFromConfig([]byte(`{"cvm-version":"0.15.5-rc.1@sha256:` + digest + `","cvm-version":"x"}`))
	require.ErrorContains(t, err, "duplicate")
}
