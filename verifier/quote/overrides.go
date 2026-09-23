//go:build !tinfoil_conformance

package quote

import (
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/tdx"
)

// overrides carries nothing in a production build: neither the verification
// clock nor the vendor trust anchors can be replaced, so a shipped binary
// cannot be made to accept expired collateral or to trust a supplied root.
// The conformance build substitutes a populated version of this type.
type overrides struct{}

func (overrides) sev() *sev.Options { return nil }
func (overrides) tdx() *tdx.Options { return nil }
