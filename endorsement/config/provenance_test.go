package config_test

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

func TestContainerProvenanceFromConfig(t *testing.T) {
	digest, other := strings.Repeat("ab", sha256.Size), strings.Repeat("cd", sha256.Size)
	const imageName = `"ghcr.io/tinfoilsh/inference-vllm`
	image := imageName + `@sha256:` + digest + `"`
	const github = `{"repository":"tinfoilsh/inference","repository_id":"902195777","workflow":"containers.yml","ref":"refs/tags/vllm-v*"}`
	const provenance = `{"github":` + github + `}`
	const unconstrained = `{"name":"router","image":"example.com/router:latest"}`
	container := func(image, provenance string) string {
		return `{"name":"model","image":` + image + `,"provenance":` + provenance + `}`
	}
	config := func(containers string) string {
		return `{"cvm-version":"0.15.5","containers":` + containers + `}`
	}
	requiring := func(image, provenance string) string { return config(`[` + container(image, provenance) + `]`) }
	edited := func(old, new string) string {
		return requiring(image, `{"github":`+strings.Replace(github, old, new, 1)+`}`)
	}
	required := func(digest string) configendorsement.ContainerProvenance {
		return configendorsement.ContainerProvenance{
			Digest: digest, Repository: "tinfoilsh/inference", RepositoryID: "902195777",
			Workflow: "containers.yml", Ref: "refs/tags/vllm-v*",
		}
	}

	for name, tt := range map[string]struct {
		config string
		want   []configendorsement.ContainerProvenance
	}{
		"no containers":    {`{"cvm-version":"0.15.5"}`, nil},
		"empty containers": {config(`[]`), nil},
		"no provenance":    {config(`[` + unconstrained + `,{"image":7}]`), nil},
		"required": {
			config(`[` + unconstrained + `,` + container(image, provenance) + `,` + container(`"@sha256:`+other+`"`, provenance) + `]`),
			[]configendorsement.ContainerProvenance{required(digest), required(other)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := configendorsement.ContainerProvenanceFromConfig([]byte(tt.config))
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	for name, config := range map[string]string{
		"not JSON":                     "containers: []\n",
		"trailing data":                config(`[]`) + `{}`,
		"repeated container member":    config(`[{"image":` + image + `,"image":` + image + `}]`),
		"containers null":              config(`null`),
		"containers not an array":      config(`{}`),
		"container null":               config(`[null]`),
		"container not an object":      config(`["model"]`),
		"provenance null":              requiring(image, `null`),
		"provenance not an object":     requiring(image, `"github"`),
		"provenance empty":             requiring(image, `{}`),
		"unknown kind":                 requiring(image, `{"gitlab":`+github+`}`),
		"second kind":                  requiring(image, `{"github":`+github+`,"gitlab":{}}`),
		"kind in another case":         requiring(image, `{"GitHub":`+github+`}`),
		"github null":                  requiring(image, `{"github":null}`),
		"github not an object":         requiring(image, `{"github":"tinfoilsh/inference"}`),
		"github without repository":    edited(`"repository":"tinfoilsh/inference",`, ``),
		"github without repository_id": edited(`"repository_id":"902195777",`, ``),
		"github without workflow":      edited(`"workflow":"containers.yml",`, ``),
		"github without ref":           edited(`,"ref":"refs/tags/vllm-v*"`, ``),
		"github unknown member":        edited(`}`, `,"environment":"release"}`),
		"github repeated member":       edited(`}`, `,"ref":"refs/heads/main"}`),
		"github number member":         edited(`"902195777"`, `902195777`),
		"github null member":           edited(`"refs/tags/vllm-v*"`, `null`),
		"image absent":                 config(`[{"provenance":` + provenance + `}]`),
		"image null":                   requiring(`null`, provenance),
		"image not a string":           requiring(`7`, provenance),
		"image by tag":                 requiring(imageName+`:latest"`, provenance),
		"image digest alone":           requiring(`"`+digest+`"`, provenance),
		"image digest uppercase":       requiring(imageName+`@sha256:`+strings.ToUpper(digest)+`"`, provenance),
		"image digest short":           requiring(imageName+`@sha256:`+digest[1:]+`"`, provenance),
		"image digest long":            requiring(imageName+`@sha256:`+digest+`a"`, provenance),
		"image digest not last":        requiring(imageName+`@sha256:`+digest+`/"`, provenance),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configendorsement.ContainerProvenanceFromConfig([]byte(config))
			require.Error(t, err)
		})
	}
}
