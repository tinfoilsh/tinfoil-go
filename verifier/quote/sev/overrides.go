//go:build !tinfoil_conformance

package sev

import "time"

// overrides carries nothing in a production build: neither the verification
// clock nor the AMD trust anchor can be replaced, so a shipped binary cannot
// be made to accept expired collateral or to trust a supplied anchor. The
// conformance build substitutes a populated version of this type.
type overrides struct{}

func (overrides) clock() time.Time { return time.Time{} }
func (overrides) root() []byte     { return nil }
