package collateral

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	"fmt"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
	"golang.org/x/mod/semver"
)

const (
	RuntimeRepo     = "tinfoilsh/cvmimage"
	RuntimeID       = "runtime"
	RuntimeV1Format = "https://tinfoil.sh/collateral/igvm-runtime/v1"
	PlatformID      = "platform"
)

type RuntimeReference struct {
	Repo   string `json:"repo"`
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
}

func (r RuntimeReference) Validate() error {
	if r.Repo != RuntimeRepo {
		return fmt.Errorf("runtime repository must be %s", RuntimeRepo)
	}
	if !semver.IsValid(r.Tag) || semver.Canonical(r.Tag) != r.Tag {
		return fmt.Errorf("runtime tag must be a canonical semantic version")
	}
	_, err := canonical.DecodeLowerHex("runtime digest", r.Digest, sha256.Size)
	return err
}

type runtimeCollateral struct {
	RuntimeReference
	Manifest string         `json:"manifest_base64"`
	Bundle   jsontext.Value `json:"sigstore_bundle"`
}

type Runtime struct {
	RuntimeReference
	Manifest []byte
	Bundle   jsontext.Value
}

func decodeRuntime(entry *Entry) (Runtime, error) {
	var c runtimeCollateral
	if err := unmarshalData(entry, entry.Format, &c); err != nil {
		return Runtime{}, err
	}
	if err := c.RuntimeReference.Validate(); err != nil {
		return Runtime{}, err
	}
	manifest, err := canonical.DecodeBase64("manifest_base64", c.Manifest)
	if err != nil {
		return Runtime{}, err
	}
	if c.Bundle.Kind() != '{' {
		return Runtime{}, fmt.Errorf("sigstore_bundle must be an object")
	}
	return Runtime{RuntimeReference: c.RuntimeReference, Manifest: manifest, Bundle: c.Bundle}, nil
}

func (r Runtime) Clone() Runtime {
	r.Manifest = slices.Clone(r.Manifest)
	r.Bundle = slices.Clone(r.Bundle)
	return r
}

// ConfigPlatform requires an unambiguous platform reference for config verification.
func (s Set) ConfigPlatform() (SigstoreRef, error) {
	if s.platformCount == 0 {
		return SigstoreRef{}, fmt.Errorf("%w: no platform reference-values entry", ErrNotFound)
	}
	if s.platformCount != 1 || s.configPlatform == nil {
		return SigstoreRef{}, fmt.Errorf("conflicting platform collateral for config verification")
	}
	return s.configPlatform.Clone(), nil
}
