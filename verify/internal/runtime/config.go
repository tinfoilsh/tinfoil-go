package runtime

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

// ConfigRuntime extracts the immutable runtime pin without changing config bytes.
// The publisher and guest own validation of the workload's other fields.
func ConfigRuntime(data []byte) (collateral.RuntimeReference, error) {
	var fields struct {
		Version string `yaml:"cvm-version"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&fields); err != nil {
		return collateral.RuntimeReference{}, fmt.Errorf("parsing config runtime pin: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return collateral.RuntimeReference{}, fmt.Errorf("config must contain exactly one YAML document")
	}
	version, digest, found := strings.Cut(fields.Version, "@sha256:")
	if !found {
		return collateral.RuntimeReference{}, fmt.Errorf("cvm-version must pin a runtime manifest SHA-256 digest")
	}
	ref := collateral.RuntimeReference{Repo: collateral.RuntimeRepo, Tag: "v" + strings.TrimPrefix(version, "v"), Digest: digest}
	if err := ref.Validate(); err != nil {
		return collateral.RuntimeReference{}, err
	}
	return ref, nil
}
