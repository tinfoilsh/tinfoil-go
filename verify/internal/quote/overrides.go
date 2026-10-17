//go:build !tinfoil_conformance

package quote

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
)

// overrides carries no trust-anchor replacements in a production build.
type overrides struct{}

func (overrides) sev(now time.Time) *sev.Options {
	return &sev.Options{VerificationTime: now}
}
func (overrides) tdx(now time.Time) *tdx.Options {
	return &tdx.Options{VerificationTime: now}
}
