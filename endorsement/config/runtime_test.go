package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

func TestRuntimeFromConfigReturnsErrorOnDecoderPanic(t *testing.T) {
	for _, config := range []string{
		"? [a]\n: 1\n<<: {b: 2}\ncvm-version: x\n",
		"<<: {b: 2}\n? [a]\n: 1\n",
		"? {a: 1}\n: 1\n<<: {b: 2}\n",
	} {
		_, err := configendorsement.RuntimeFromConfig([]byte(config))
		require.ErrorContains(t, err, "parsing config runtime pin", "config %q", config)
	}
}

// From JSONConfigMinVersion a config is canonical JSON and YAML is refused;
// earlier versions keep YAML.
func TestRuntimeFromConfigFormatFollowsThePinnedVersion(t *testing.T) {
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
		"JSON for a later version":       {json("0.16.0"), "v0.16.0"},
		"YAML before the JSON version":   {yaml("0.15.5-rc.0"), "v0.15.5-rc.0"},
		"YAML for an earlier release":    {yaml("0.15.4"), "v0.15.4"},
		"flow-style YAML before it":      {json("0.15.4"), "v0.15.4"},
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
	for name, tt := range map[string]struct{ config, wantError string }{
		"YAML at the first JSON version": {yaml("0.15.5-rc.1"), "take a JSON config"},
		"YAML with build metadata":       {yaml("0.15.5-rc.1+gpu"), "take a JSON config"},
		"YAML for a later version":       {yaml("1.0.0"), "take a JSON config"},
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
