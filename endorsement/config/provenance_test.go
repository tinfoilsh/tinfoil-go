package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

func TestContainerProvenanceFromConfig(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	const github = `    provenance:
      github:
        repository: tinfoilsh/inference
        repository_id: 902195777
        workflow: containers.yml
        ref: refs/tags/vllm-v*
`
	config := func(image, provenance string) []byte {
		return []byte("cvm-version: 0.15.5\ncontainers:\n  - name: router\n    image: example.com/router@sha256:" + strings.Repeat("cd", 32) +
			"\n  - name: model\n    image: " + image + "\n" + provenance)
	}
	image := "ghcr.io/tinfoilsh/inference-vllm@sha256:" + digest

	required, err := configendorsement.ContainerProvenanceFromConfig(config(image, github))
	require.NoError(t, err)
	require.Equal(t, []configendorsement.ContainerProvenance{{
		Container: "model", Digest: digest, Repository: "tinfoilsh/inference", RepositoryID: "902195777",
		Workflow: "containers.yml", Ref: "refs/tags/vllm-v*",
	}}, required)

	for _, absent := range []string{"", "    provenance:\n", "    provenance: null\n"} {
		required, err := configendorsement.ContainerProvenanceFromConfig(config(image, absent))
		require.NoError(t, err)
		require.Empty(t, required, "provenance %q", absent)
	}

	replace := func(old, new string) string { return strings.Replace(github, old, new, 1) }
	for name, tt := range map[string]struct {
		image, provenance, wantError string
	}{
		"unknown kind of requirement": {image, "    provenance:\n      gitlab:\n        project: a/b\n", `provenance has unknown field "gitlab"`},
		"extra requirement":           {image, github + "      require_signed_commits: true\n", `provenance has unknown field "require_signed_commits"`},
		"extra detail":                {image, github + "        environment: release\n", `provenance.github has unknown field "environment"`},
		"empty requirement":           {image, "    provenance: {}\n", "provenance.github is required"},
		"not a mapping":               {image, "    provenance: tinfoilsh/inference\n", "provenance must be a mapping"},
		"duplicate detail":            {image, github + "        ref: refs/heads/main\n", `provenance.github has duplicate field "ref"`},
		"repository without owner":    {image, replace("tinfoilsh/inference", "inference"), "must be owner/name"},
		"missing repository ID":       {image, replace("        repository_id: 902195777\n", ""), "repository_id"},
		"workflow path":               {image, replace("containers.yml", "sub/containers.yml"), "workflow file name"},
		"pull request ref":            {image, replace("refs/tags/vllm-v*", "refs/pull/*/merge"), "tag or branch ref pattern"},
		"ref with identity separator": {image, replace("refs/tags/vllm-v*", "refs/tags/v@refs/heads/main"), "tag or branch ref pattern"},
		"image without digest":        {"ghcr.io/tinfoilsh/inference-vllm:latest", github, "must pin a SHA-256 digest"},
		"second document":             {image, github + "---\ncontainers: []\n", "exactly one YAML document"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configendorsement.ContainerProvenanceFromConfig(config(tt.image, tt.provenance))
			require.ErrorContains(t, err, tt.wantError)
		})
	}

}

// A mapping that combines a non-scalar key with a merge key makes yaml.v3
// panic while decoding into a struct.
func TestContainerProvenanceFromConfigReturnsErrorOnDecoderPanic(t *testing.T) {
	for _, config := range []string{
		"? [a]\n: 1\n<<: {b: 2}\ncontainers: []\n",
		"<<: {b: 2}\n? [a]\n: 1\n",
		"? {a: 1}\n: 1\n<<: {b: 2}\n",
	} {
		_, err := configendorsement.ContainerProvenanceFromConfig([]byte(config))
		require.ErrorContains(t, err, "parsing config provenance", "config %q", config)
	}
}
