//go:build !tinfoil_conformance

package verifier

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/internal/quote"
)

// overrides holds nothing in a production build: there is no way to replace a
// trust anchor.
type overrides struct{}

// quoteOptions carries nothing to the CPU evidence layer in a production
// build, so that layer uses its own embedded vendor roots and reads the clock
// itself. The conformance build passes the appraisal instant down instead.
func (v *Verifier) quoteOptions(time.Time) *quote.Options { return nil }
