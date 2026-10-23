package config

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

const RuntimeRepo = "tinfoilsh/cvmimage"

type RuntimeReference struct {
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

func (r RuntimeReference) Validate() error {
	if r.Repo != RuntimeRepo {
		return fmt.Errorf("runtime repository must be %s", RuntimeRepo)
	}
	if !semver.IsValid(r.Tag) || semver.Canonical(r.Tag)+semver.Build(r.Tag) != r.Tag {
		return fmt.Errorf("runtime tag must be a full semantic version")
	}
	_, err := canonical.DecodeLowerHex("runtime digest", r.Digest, sha256.Size)
	return err
}

// RuntimeFromConfig extracts the immutable runtime pin without changing config bytes.
// The publisher and guest own validation of the workload's other fields.
func RuntimeFromConfig(data []byte) (RuntimeReference, error) {
	var fields struct {
		Version string `yaml:"cvm-version"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&fields); err != nil {
		return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return RuntimeReference{}, fmt.Errorf("config must contain exactly one YAML document")
	}
	version, digest, found := strings.Cut(fields.Version, "@sha256:")
	if !found {
		return RuntimeReference{}, fmt.Errorf("cvm-version must pin a runtime manifest SHA-256 digest")
	}
	ref := RuntimeReference{Repo: RuntimeRepo, Tag: "v" + strings.TrimPrefix(version, "v"), Digest: digest}
	if err := ref.Validate(); err != nil {
		return RuntimeReference{}, err
	}
	return ref, nil
}
