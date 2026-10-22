//go:build tinfoil_conformance

package verify

import (
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

// overrides carries the synthetic vendor roots set by
// DangerousTestOnlyWithVendorRoots; nil entries keep the embedded anchors.
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

// DangerousTestOnlyWithSigstoreRoot replaces the embedded Sigstore trusted
// root, so the conformance harness can authenticate reference values signed by
// a synthetic CA. A supplied root destroys the guarantee that those values came
// from Tinfoil's release workflows, which is why this exists only in the
// conformance build. A nil rootJSON keeps the embedded root.
func DangerousTestOnlyWithSigstoreRoot(rootJSON []byte) Option {
	return func(v *Verifier) error {
		if rootJSON == nil {
			return nil
		}
		client, err := endorsement.NewClientFromJSON(rootJSON)
		if err != nil {
			return err
		}
		v.endorsements = client
		return nil
	}
}

// DangerousTestOnlyWithVendorRoots replaces the embedded AMD and Intel trust
// anchors, so the conformance harness can authenticate synthetic CPU evidence.
// A supplied anchor destroys the guarantee that evidence chains to AMD or
// Intel, which is why this exists only in the conformance build. A nil entry
// keeps the embedded anchor for that platform.
func DangerousTestOnlyWithVendorRoots(amdRootPEM, intelRootPEM []byte) Option {
	return func(v *Verifier) error {
		v.overrides.amdRootPEM = amdRootPEM
		v.overrides.intelRootPEM = intelRootPEM
		return nil
	}
}
