package config

import (
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

const RuntimeRepo = "tinfoilsh/cvmimage"

const runtimeDigestSeparator = "@sha256:"

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
//
// It reads the cvm-version member of a JSON config and nothing else: the
// guest decides which configs it boots. The YAML that earlier enclave
// versions measure is not read here: a caller that has such a config reads
// its cvm-version itself and uses RuntimeFromPin.
func RuntimeFromConfig(data []byte) (RuntimeReference, error) {
	if len(data) > MaxConfigSize {
		return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: the config is larger than %d bytes", MaxConfigSize)
	}
	pin, err := jsonConfigPin(data)
	if err != nil {
		return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: not a JSON config that states cvm-version (%w); YAML configs are not read", err)
	}
	return RuntimeFromPin(pin)
}

// RuntimeFromPin reads the runtime that a cvm-version value pins:
// <version>@sha256:<manifest digest>.
func RuntimeFromPin(pin string) (RuntimeReference, error) {
	version, digest, found := strings.Cut(pin, runtimeDigestSeparator)
	if !found {
		return RuntimeReference{}, fmt.Errorf("cvm-version must pin a runtime manifest SHA-256 digest")
	}
	ref := RuntimeReference{Repo: RuntimeRepo, Tag: "v" + strings.TrimPrefix(version, "v"), Digest: digest}
	if err := ref.Validate(); err != nil {
		return RuntimeReference{}, err
	}
	return ref, nil
}

// jsonConfigPin returns the cvm-version that data states, read as a JSON
// object.
func jsonConfigPin(data []byte) (string, error) {
	var fields struct {
		Version *string `json:"cvm-version"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", err
	}
	if fields.Version == nil {
		return "", fmt.Errorf("no cvm-version member")
	}
	return *fields.Version, nil
}
