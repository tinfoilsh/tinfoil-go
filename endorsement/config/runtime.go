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
	if len(data) > MaxConfigSize {
		return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: config exceeds %d bytes", MaxConfigSize)
	}
	var fields struct {
		Version string `json:"cvm-version"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: %w", err)
	}
	return RuntimeFromPin(fields.Version)
}

// RuntimeFromPin reads the runtime that a cvm-version value pins.
func RuntimeFromPin(pin string) (RuntimeReference, error) {
	version, digest, found := strings.Cut(pin, "@sha256:")
	if !found {
		return RuntimeReference{}, fmt.Errorf("cvm-version must pin a runtime manifest SHA-256 digest")
	}
	ref := RuntimeReference{Repo: RuntimeRepo, Tag: "v" + strings.TrimPrefix(version, "v"), Digest: digest}
	if err := ref.Validate(); err != nil {
		return RuntimeReference{}, err
	}
	return ref, nil
}
