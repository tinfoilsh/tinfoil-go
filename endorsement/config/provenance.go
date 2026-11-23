package config

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"

	"gopkg.in/yaml.v3"
)

const (
	provenanceField       = "provenance"
	githubProvenanceField = "provenance.github"
)

var (
	githubRepositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	githubWorkflowPattern   = regexp.MustCompile(`^[A-Za-z0-9_.-]+\.ya?ml$`)
	githubRefPattern        = regexp.MustCompile(`^refs/(tags|heads)/[A-Za-z0-9_.*-]+(/[A-Za-z0-9_.*-]+)*$`)
	imageDigestPattern      = regexp.MustCompile(`@sha256:([0-9a-f]{64})$`)
)

// ContainerProvenance is the build a config requires for one container image:
// a GitHub Actions workflow run in a named repository. Ref is a tag or branch
// ref pattern in which "*" matches any run of characters other than "/".
type ContainerProvenance struct {
	Container    string
	Digest       string
	Repository   string
	RepositoryID string
	Workflow     string
	Ref          string
}

// ContainerProvenanceFromConfig returns the build requirements a config
// declares, in container order. It rejects a requirement it cannot read in
// full, so a verifier never treats an unknown kind of requirement as met.
func ContainerProvenanceFromConfig(data []byte) (requirements []ContainerProvenance, err error) {
	// yaml.v3 panics on some malformed documents instead of returning an error.
	defer func() {
		if r := recover(); r != nil {
			requirements, err = nil, fmt.Errorf("parsing config provenance: %v", r)
		}
	}()
	var fields struct {
		Containers []struct {
			Name       string    `yaml:"name"`
			Image      string    `yaml:"image"`
			Provenance yaml.Node `yaml:"provenance"`
		} `yaml:"containers"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&fields); err != nil {
		return nil, fmt.Errorf("parsing config provenance: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("config must contain exactly one YAML document")
	}
	for index, container := range fields.Containers {
		node := resolveAlias(&container.Provenance)
		if node.Kind == 0 || node.Tag == "!!null" {
			continue
		}
		requirement, err := githubProvenance(node)
		if err != nil {
			return nil, fmt.Errorf("containers[%d].%w", index, err)
		}
		digest := imageDigestPattern.FindStringSubmatch(container.Image)
		if digest == nil {
			return nil, fmt.Errorf("containers[%d].image must pin a SHA-256 digest to declare provenance", index)
		}
		requirement.Container, requirement.Digest = container.Name, digest[1]
		requirements = append(requirements, requirement)
	}
	return requirements, nil
}

func githubProvenance(node *yaml.Node) (ContainerProvenance, error) {
	var provenance struct {
		GitHub yaml.Node `yaml:"github"`
	}
	if err := decodeKnownFields(node, provenanceField, &provenance, "github"); err != nil {
		return ContainerProvenance{}, err
	}
	var github struct {
		Repository   string `yaml:"repository"`
		RepositoryID int64  `yaml:"repository_id"`
		Workflow     string `yaml:"workflow"`
		Ref          string `yaml:"ref"`
	}
	if provenance.GitHub.Kind == 0 {
		return ContainerProvenance{}, fmt.Errorf("%s is required", githubProvenanceField)
	}
	if err := decodeKnownFields(resolveAlias(&provenance.GitHub), githubProvenanceField, &github, "repository", "repository_id", "workflow", "ref"); err != nil {
		return ContainerProvenance{}, err
	}
	switch {
	case !githubRepositoryPattern.MatchString(github.Repository):
		return ContainerProvenance{}, fmt.Errorf("%s.repository %q must be owner/name", githubProvenanceField, github.Repository)
	case github.RepositoryID <= 0:
		return ContainerProvenance{}, fmt.Errorf("%s.repository_id must be the repository's numeric ID", githubProvenanceField)
	case !githubWorkflowPattern.MatchString(github.Workflow):
		return ContainerProvenance{}, fmt.Errorf("%s.workflow %q must be a workflow file name", githubProvenanceField, github.Workflow)
	case !githubRefPattern.MatchString(github.Ref):
		return ContainerProvenance{}, fmt.Errorf("%s.ref %q must be a tag or branch ref pattern", githubProvenanceField, github.Ref)
	}
	return ContainerProvenance{
		Repository: github.Repository, RepositoryID: strconv.FormatInt(github.RepositoryID, 10),
		Workflow: github.Workflow, Ref: github.Ref,
	}, nil
}

func decodeKnownFields(node *yaml.Node, name string, target any, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be a mapping", name)
	}
	seen := map[string]bool{}
	for index := 0; index < len(node.Content); index += 2 {
		field := node.Content[index].Value
		if seen[field] {
			return fmt.Errorf("duplicate %s field %q", name, field)
		}
		seen[field] = true
		if !slices.Contains(allowed, field) {
			return fmt.Errorf("unknown %s field %q", name, field)
		}
	}
	if err := node.Decode(target); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func resolveAlias(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		return node.Alias
	}
	return node
}
