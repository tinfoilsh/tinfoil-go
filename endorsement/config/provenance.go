package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

// imageDigestPrefix precedes the hex SHA-256 digest that ends a pinned image
// reference.
const imageDigestPrefix = "@sha256:"

// ContainerProvenance is the build that a config requires for the container
// image with the lowercase hex SHA-256 Digest: a run of a GitHub Actions
// workflow of a repository, at a ref and a source commit.
type ContainerProvenance struct {
	Digest       string
	Repository   string
	RepositoryID string
	Workflow     string
	Ref          string
	Commit       string
}

// ContainerProvenanceFromConfig returns the builds that a config requires, in
// container order. A requirement of any shape but the one it reads is an
// error, so that an unknown kind of requirement is never treated as met.
// The publisher and guest own validation of the values.
func ContainerProvenanceFromConfig(data []byte) ([]ContainerProvenance, error) {
	var config struct {
		Containers jsontext.Value `json:"containers"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing config containers: %w", err)
	}
	if len(config.Containers) == 0 {
		return nil, nil
	}
	var containers []*struct {
		Image      jsontext.Value `json:"image"`
		Provenance jsontext.Value `json:"provenance"`
	}
	if err := json.Unmarshal(config.Containers, &containers); err != nil || config.Containers.Kind() != '[' {
		return nil, fmt.Errorf("config containers must be an array of objects")
	}
	var required []ContainerProvenance
	for index, container := range containers {
		if container == nil {
			return nil, fmt.Errorf("config containers must be an array of objects")
		}
		if len(container.Provenance) == 0 {
			continue
		}
		var provenance struct {
			GitHub *struct {
				Repository   *string `json:"repository"`
				RepositoryID *string `json:"repository_id"`
				Workflow     *string `json:"workflow"`
				Ref          *string `json:"ref"`
				Commit       *string `json:"commit"`
			} `json:"github"`
		}
		err := json.Unmarshal(container.Provenance, &provenance, json.RejectUnknownMembers(true))
		github := provenance.GitHub
		if err != nil || github == nil || github.Repository == nil || github.RepositoryID == nil || github.Workflow == nil || github.Ref == nil || github.Commit == nil {
			return nil, fmt.Errorf("containers[%d].provenance must hold only github, with only the strings repository, repository_id, workflow, ref and commit", index)
		}
		var image string
		if err := json.Unmarshal(container.Image, &image); err != nil {
			return nil, fmt.Errorf("containers[%d].image must be a string", index)
		}
		split := len(image) - hex.EncodedLen(sha256.Size)
		if split < 0 || !strings.HasSuffix(image[:split], imageDigestPrefix) || !canonical.IsLowerHex(image[split:]) {
			return nil, fmt.Errorf("containers[%d].image must end with %s and a lowercase hex digest", index, imageDigestPrefix)
		}
		required = append(required, ContainerProvenance{
			Digest: image[split:], Repository: *github.Repository, RepositoryID: *github.RepositoryID,
			Workflow: *github.Workflow, Ref: *github.Ref, Commit: *github.Commit,
		})
	}
	return required, nil
}
