package document

import (
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

// ConfigEndorsement returns a copy of the decoded, unauthenticated config approval.
func (d *Document) ConfigEndorsement() (collateral.ConfigEndorsement, error) {
	if d.collateral.Config == nil {
		return collateral.ConfigEndorsement{}, fmt.Errorf("%w: document carries no %q reference-values entry", collateral.ErrNotFound, collateral.ConfigID)
	}
	return d.collateral.Config.Clone(), nil
}

// IGVMRuntime returns a copy of the decoded, unauthenticated runtime approval.
func (d *Document) IGVMRuntime() (collateral.IGVMRuntime, error) {
	if d.collateral.Runtime == nil {
		return collateral.IGVMRuntime{}, fmt.Errorf("%w: document carries no %q reference-values entry", collateral.ErrNotFound, collateral.RuntimeID)
	}
	return d.collateral.Runtime.Clone(), nil
}

func (d *Document) IGVMPlatform() (collateral.SigstoreRef, error) {
	return d.collateral.IGVMPlatform()
}
