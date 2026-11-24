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
	"gopkg.in/yaml.v3"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

const RuntimeRepo = "tinfoilsh/cvmimage"

// JSONConfigMinVersion is the first cvm-version whose config is JSON. A
// config that pins it or a later version is canonical JSON, and YAML is
// refused; earlier versions keep YAML.
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
func RuntimeFromConfig(data []byte) (ref RuntimeReference, err error) {
	if pin, ok := jsonConfigPin(data); ok && requiresJSON(pin) {
		if err := checkJSONConfigForm(data); err != nil {
			return RuntimeReference{}, fmt.Errorf("parsing config runtime pin: %w", err)
		}
		return runtimeFromPin(pin)
	}
	// yaml.v3 panics on some malformed documents, such as a mapping with a
	// non-scalar key and a merge key, instead of returning an error.
	defer func() {
		if r := recover(); r != nil {
			ref, err = RuntimeReference{}, fmt.Errorf("parsing config runtime pin: %v", r)
		}
	}()
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
	ref, err = runtimeFromPin(fields.Version)
	if err != nil {
		return RuntimeReference{}, err
	}
	if requiresJSON(fields.Version) {
		return RuntimeReference{}, fmt.Errorf("cvm-version %s and later take a JSON config", JSONConfigMinVersion)
	}
	return ref, nil
}

func runtimeFromPin(pin string) (RuntimeReference, error) {
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

// jsonConfigPin returns the cvm-version of data read as a JSON object, and
// whether data is one that states it.
func jsonConfigPin(data []byte) (string, bool) {
	var fields struct {
		Version *string `json:"cvm-version"`
	}
	if err := json.Unmarshal(data, &fields); err != nil || fields.Version == nil {
		return "", false
	}
	return *fields.Version, true
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
