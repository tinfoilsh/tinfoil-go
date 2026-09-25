//go:build tinfoil_conformance

package verifier

import (
	"fmt"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote"
)

// quoteOptions hands the CPU evidence layer the instant this verification is
// being appraised at, so a replayed document is judged consistently by both
// the freshness witnesses and the certificate and CRL validity windows.
func (v *Verifier) quoteOptions(now time.Time) *quote.Options {
	opts := &quote.Options{}
	opts.DangerousTestOnlySetClock(now)
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

// ReferenceValues authenticates the document's code and platform artifacts and
// their freshness witnesses, under this verifier's policy and clock.
//
// VerifyV3 returns one error for the whole flow, but the conformance adapter
// must report which layer rejected a document, so it drives the layers itself.
// Exposing this step lets it do that against the same code production runs,
// rather than against its own copy.
func (v *Verifier) ReferenceValues(doc *document.Document, repo string) (*provenance.Code, *provenance.PlatformEndorsements, time.Time, error) {
	return v.authenticateReferenceValues(doc, repo, v.now())
}
