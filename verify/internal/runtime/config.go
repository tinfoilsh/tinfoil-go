package runtime

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	cvmruntime "github.com/tinfoilsh/tinfoil-config/runtime"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
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
	ref, err := cvmruntime.ParseReference(fields.Version)
	if err != nil {
		return collateral.RuntimeReference{}, err
	}
	return collateral.RuntimeReference{Repo: collateral.RuntimeRepo, Tag: ref.Tag, Variant: ref.Variant, Digest: ref.Digest}, nil
}
