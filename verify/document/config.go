package document

import (
	"encoding/json/jsontext"
	"fmt"
	"slices"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// ConfigEndorsement returns a copy of the decoded, unauthenticated config approval.
func (d *Document) ConfigEndorsement() (collateral.ConfigEndorsement, error) {
	if d.collateral.Config == nil {
		return collateral.ConfigEndorsement{}, fmt.Errorf("%w: document carries no %q reference-values entry", collateral.ErrNotFound, collateral.ConfigID)
	}
	return d.collateral.Config.Clone(), nil
}

// Runtime returns a copy of the decoded, unauthenticated runtime approval.
func (d *Document) Runtime() (collateral.Runtime, error) {
	if d.collateral.Runtime == nil {
		return collateral.Runtime{}, fmt.Errorf("%w: document carries no %q reference-values entry", collateral.ErrNotFound, collateral.RuntimeID)
	}
	return d.collateral.Runtime.Clone(), nil
}

func (d *Document) ConfigPlatform() (collateral.SigstoreRef, error) {
	return d.collateral.ConfigPlatform()
}

// ContainerProvenance returns a copy of the unauthenticated build attestation,
// a Sigstore bundle, of the container image with the given lowercase hex
// SHA-256 digest.
func (d *Document) ContainerProvenance(digest string) (jsontext.Value, error) {
	bundle, ok := d.collateral.Containers[digest]
	if !ok {
		return nil, fmt.Errorf("%w: document carries no %s reference-values entry for sha256:%s", collateral.ErrNotFound, collateral.ContainerProvenanceV1Format, digest)
	}
	return slices.Clone(bundle), nil
}
