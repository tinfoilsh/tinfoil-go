//go:build tinfoil_conformance

package verify

import (
	"bytes"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

// overrides carries the synthetic vendor roots set by
// DangerousTestOnlyNewVerifier; nil entries keep the embedded anchors.
type overrides struct {
	amdRootPEM   []byte
	intelRootPEM []byte
}

// quoteOptions hands the CPU evidence layer any synthetic vendor roots.
func (v *Verifier) quoteOptions() *quote.Options {
	opts := &quote.Options{}
	opts.DangerousTestOnlySetRoots(v.overrides.amdRootPEM, v.overrides.intelRootPEM)
	return opts
}

// DangerousTestOnlyRoots replaces trust anchors embedded in this module, so
// that the conformance harness can authenticate synthetic collateral. A
// supplied anchor destroys the guarantee that it protects, which is why this
// exists only in the conformance build. A nil member keeps the embedded anchor.
type DangerousTestOnlyRoots struct {
	// SigstoreRootJSON replaces the Sigstore trusted root, which otherwise
	// guarantees that reference values came from Tinfoil's release workflows.
	SigstoreRootJSON []byte
	// AMDRootPEM and IntelRootPEM replace the vendor anchors, which otherwise
	// guarantee that CPU evidence chains to AMD or Intel.
	AMDRootPEM   []byte
	IntelRootPEM []byte
}

// DangerousTestOnlyNewVerifier is NewVerifier with the trust anchors that
// roots supplies in place of the embedded ones.
func DangerousTestOnlyNewVerifier(config ConfigTrust, policy Policy, roots DangerousTestOnlyRoots) (*Verifier, error) {
	endorsements, err := endorsement.NewDefaultClient()
	if roots.SigstoreRootJSON != nil {
		endorsements, err = endorsement.NewClientFromJSON(roots.SigstoreRootJSON)
	}
	if err != nil {
		return nil, usageError(err)
	}
	return newVerifier(config, policy, endorsements, overrides{
		amdRootPEM:   bytes.Clone(roots.AMDRootPEM),
		intelRootPEM: bytes.Clone(roots.IntelRootPEM),
	})
}
