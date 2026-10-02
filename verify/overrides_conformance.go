//go:build tinfoil_conformance

package verify

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

// overrides carries the synthetic vendor roots set by
// DangerousTestOnlyWithVendorRoots; nil entries keep the embedded anchors.
type overrides struct {
	amdRootPEM   []byte
	intelRootPEM []byte
}

// quoteOptions hands the CPU evidence layer the instant this verification is
// being appraised at, so a replayed document is judged consistently by both
// the freshness witnesses and the certificate and CRL validity windows, along
// with any synthetic vendor roots.
func (v *Verifier) quoteOptions(now time.Time) *quote.Options {
	opts := &quote.Options{}
	opts.DangerousTestOnlySetClock(now)
	opts.DangerousTestOnlySetRoots(v.overrides.amdRootPEM, v.overrides.intelRootPEM)
	return opts
}

// DangerousTestOnlyWithClock replaces the appraisal clock, so the conformance
// harness can replay a frozen document at its capture time. A rewound clock
// accepts witnesses and collateral that have since expired, which is why this
// exists only in the conformance build.
func DangerousTestOnlyWithClock(now func() time.Time) Option {
	return func(v *Verifier) error {
		if now == nil {
			return fmt.Errorf("clock must not be nil")
		}
		v.now = now
		return nil
	}
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
		client, err := provenance.NewClientFromJSON(rootJSON)
		if err != nil {
			return err
		}
		v.provenance = client
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

// VerifyV3WithLayer is VerifyV3, also naming the layer that rejected the
// document: "envelope", "provenance", "quote" or "policy", or "" when the
// Verifier itself was unusable or the document verified. The conformance
// adapter reports that layer, so this runs exactly the code VerifyV3 does.
func (v *Verifier) VerifyV3WithLayer(docBytes, nonce []byte, repo string) (*Verification, string, error) {
	verified, layer, err := v.verifyV3(docBytes, nonce, repo)
	return verified, string(layer), err
}
