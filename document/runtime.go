package document

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	"fmt"

	"golang.org/x/mod/semver"
)

const (
	RuntimeRepo                   = "tinfoilsh/cvmimage"
	RuntimeCollateralID           = "runtime"
	CollateralIGVMRuntimeV1Format = "https://tinfoil.sh/collateral/igvm-runtime/v1"
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
	_, err := decodeLowerHex("runtime digest", r.Digest, sha256.Size)
	return err
}

type runtimeCollateral struct {
	RuntimeReference
	Manifest string         `json:"manifest_base64"`
	Bundle   jsontext.Value `json:"sigstore_bundle"`
}

type IGVMRuntime struct {
	RuntimeReference
	Manifest []byte
	Bundle   jsontext.Value
}

func (d *Document) IGVMRuntime() (IGVMRuntime, error) {
	entry, err := d.uniqueReferenceValues(RuntimeCollateralID, CollateralIGVMRuntimeV1Format)
	if err != nil {
		return IGVMRuntime{}, err
	}
	c, err := decodeCollateral[runtimeCollateral](entry)
	if err != nil {
		return IGVMRuntime{}, err
	}
	if err := c.RuntimeReference.Validate(); err != nil {
		return IGVMRuntime{}, err
	}
	manifest, err := decodeCanonicalBase64("manifest_base64", c.Manifest)
	if err != nil {
		return IGVMRuntime{}, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(c.Bundle), []byte("{")) {
		return IGVMRuntime{}, fmt.Errorf("sigstore_bundle must be an object")
	}
	return IGVMRuntime{RuntimeReference: c.RuntimeReference, Manifest: manifest, Bundle: c.Bundle}, nil
}
