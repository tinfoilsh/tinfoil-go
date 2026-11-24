package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

const RuntimeRepo = "tinfoilsh/cvmimage"

// JSONConfigMinVersion is the first cvm-version whose config is JSON. A
// config that pins it or a later version is canonical JSON. Earlier versions
// measure YAML, which this module does not read.
const JSONConfigMinVersion = "v0.15.5-rc.1"

const (
	runtimeDigestSeparator = "@sha256:"
	// maxJSONInteger is the largest integer every JSON implementation reads
	// exactly, 2^53-1.
	maxJSONInteger = 1<<53 - 1
)

var jsonIntegerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

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
// It reads a JSON config, which is what cvm-version JSONConfigMinVersion and
// later measure. The YAML that earlier versions measure is not read here: a
// caller that has such a config reads its cvm-version itself and uses
// RuntimeFromPin.
func RuntimeFromConfig(data []byte) (RuntimeReference, error) {
	if len(data) > MaxConfigSize {
		return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: the config is larger than %d bytes", MaxConfigSize)
	}
	pin, err := jsonConfigPin(data)
	if err != nil {
		return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: not a JSON config that states cvm-version (%w); the YAML configs of versions before %s are not read", err, JSONConfigMinVersion)
	}
	ref, err := RuntimeFromPin(pin)
	if err != nil {
		return RuntimeReference{}, err
	}
	if !requiresJSON(pin) {
		return RuntimeReference{}, fmt.Errorf("a JSON config pins cvm-version %s or later", JSONConfigMinVersion)
	}
	if err := checkJSONConfigForm(data); err != nil {
		return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: %w", err)
	}
	return ref, nil
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

// requiresJSON reports whether a config with this cvm-version must be JSON.
func requiresJSON(pin string) bool {
	version, _, _ := strings.Cut(pin, runtimeDigestSeparator)
	return semver.Compare("v"+strings.TrimPrefix(version, "v"), JSONConfigMinVersion) >= 0
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

// checkJSONConfigForm requires the one byte form a JSON config has: RFC 8785
// canonical JSON whose numbers are integers that every implementation reads
// exactly, without null. No two parsers can then read its bytes differently.
func checkJSONConfigForm(data []byte) error {
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	for {
		switch decoder.PeekKind() {
		case 'n':
			return fmt.Errorf("null is not allowed in a JSON config")
		case '0':
			number, err := decoder.ReadValue()
			if err != nil {
				return err
			}
			integer, err := strconv.ParseInt(string(number), 10, 64)
			if !jsonIntegerPattern.Match(number) || err != nil || integer > maxJSONInteger || integer < -maxJSONInteger {
				return fmt.Errorf("number %s in a JSON config is not an integer between -(2^53-1) and 2^53-1", number)
			}
			continue
		}
		if _, err := decoder.ReadToken(); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	canonical := jsontext.Value(bytes.Clone(data))
	if err := canonical.Canonicalize(); err != nil {
		return err
	}
	if !bytes.Equal(canonical, data) {
		return fmt.Errorf("JSON config is not in canonical form (RFC 8785)")
	}
	return nil
}
