package collateral

import (
	"crypto/sha256"
	"encoding/json/jsontext"

	"github.com/tinfoilsh/tinfoil-go/internal/canonical"
)

// ContainerProvenanceV1Format carries the build attestation of one container
// image {digest, sigstore_bundle}.
const ContainerProvenanceV1Format = "https://tinfoil.sh/collateral/container-provenance/v1"

// containerProvenanceData is the data of a ContainerProvenanceV1Format entry:
// the lowercase hex SHA-256 digest of an image and its build attestation.
type containerProvenanceData struct {
	Digest         string         `json:"digest"`
	SigstoreBundle jsontext.Value `json:"sigstore_bundle"`
}

func decodeContainerProvenance(entry *Entry) (containerProvenanceData, error) {
	var data containerProvenanceData
	if err := unmarshalData(entry, entry.Format, &data); err != nil {
		return data, err
	}
	if _, err := canonical.DecodeLowerHex("container digest", data.Digest, sha256.Size); err != nil {
		return data, err
	}
	return data, requireBundle(entry, data.SigstoreBundle)
}
