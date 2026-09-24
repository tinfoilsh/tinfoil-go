//go:build tinfoil_conformance

package verifier

import (
	"fmt"
	"time"

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
