package collateral

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

// ContainerProvenanceV1Format carries the build attestation of one container
// image {digest, sigstore_bundle}, for a config that requires one.
const ContainerProvenanceV1Format = "https://tinfoil.sh/collateral/container-provenance/v1"

type containerProvenanceData struct {
	Digest         string         `json:"digest"`
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
}

// ContainerProvenance is a decoded, unauthenticated build attestation for the
// image with the lowercase hex SHA-256 Digest.
type ContainerProvenance struct {
	Digest string
	Bundle jsontext.Value
}

func decodeContainerProvenance(entry *Entry) (ContainerProvenance, error) {
	var data containerProvenanceData
	if err := unmarshalData(entry, entry.Format, &data); err != nil {
		return ContainerProvenance{}, err
	}
	if _, err := canonical.DecodeLowerHex("container digest", data.Digest, sha256.Size); err != nil {
		return ContainerProvenance{}, err
	}
	if err := requireBundle(entry, data.SigstoreBundle); err != nil {
		return ContainerProvenance{}, err
	}
	return ContainerProvenance{Digest: data.Digest, Bundle: data.SigstoreBundle}, nil
}

// Clone returns a deep copy of p.
func (p ContainerProvenance) Clone() ContainerProvenance {
	p.Bundle = slices.Clone(p.Bundle)
	return p
}
