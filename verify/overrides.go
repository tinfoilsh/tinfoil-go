//go:build !tinfoil_conformance

package verify

import (
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote"
)

// overrides holds nothing in a production build: there is no way to replace a
// trust anchor.
type overrides struct{}

// quoteOptions carries nothing to the CPU evidence layer in a production
// build, so that layer uses its own embedded vendor roots.
func (v *Verifier) quoteOptions() *quote.Options { return nil }
