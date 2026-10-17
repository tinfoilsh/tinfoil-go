//go:build !tinfoil_conformance

package verify

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

// overrides holds nothing in a production build: there is no way to replace a
// trust anchor.
type overrides struct{}

// quoteOptions carries the appraisal instant while retaining embedded vendor roots.
func (v *Verifier) quoteOptions(now time.Time) *quote.Options {
	return &quote.Options{VerificationTime: now}
}
