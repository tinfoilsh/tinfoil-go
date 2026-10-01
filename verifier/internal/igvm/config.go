package igvm

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
)

const runtimeArtifactsURL = "https://images.tinfoil.sh/cvm"

// ConfigRuntime extracts the immutable runtime pin without changing config bytes.
// The publisher and guest own validation of the workload's other fields.
func ConfigRuntime(data []byte) (document.RuntimeReference, error) {
	var fields struct {
		Version string `yaml:"cvm-version"`
		Source  *struct {
			Repo      string `yaml:"repo"`
			Artifacts string `yaml:"artifacts"`
		} `yaml:"cvm-source"`
	}
	if len(data) == 0 || len(data) > endorsement.MaxConfigSize {
		return document.RuntimeReference{}, fmt.Errorf("config size is outside allowed bounds")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&fields); err != nil {
		return document.RuntimeReference{}, fmt.Errorf("parsing config runtime pin: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return document.RuntimeReference{}, fmt.Errorf("config must contain exactly one YAML document")
	}
	if fields.Source != nil && (fields.Source.Repo != document.RuntimeRepo || fields.Source.Artifacts != runtimeArtifactsURL) {
		return document.RuntimeReference{}, fmt.Errorf("IGVM v1 requires the Tinfoil runtime source")
	}
	version, digest, found := strings.Cut(fields.Version, "@sha256:")
	if !found {
		return document.RuntimeReference{}, fmt.Errorf("cvm-version must pin a runtime manifest SHA-256 digest")
	}
	ref := document.RuntimeReference{Repo: document.RuntimeRepo, Tag: "v" + strings.TrimPrefix(version, "v"), Digest: digest}
	if err := ref.Validate(); err != nil {
		return document.RuntimeReference{}, err
	}
	return ref, nil
}
