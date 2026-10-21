//go:build !tinfoil_conformance

package quote

import (
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
)

// overrides carries nothing in a production build: the vendor trust anchors
// cannot be replaced, so a shipped binary cannot be made to trust a supplied
// root. The conformance build substitutes a populated version of this type.
type overrides struct{}

func (overrides) sev() *sev.Options { return nil }
func (overrides) tdx() *tdx.Options { return nil }
