//go:build !tinfoil_conformance

package sev

// overrides carries nothing in a production build: the AMD trust anchor
// cannot be replaced, so a shipped binary cannot be made to trust a supplied
// anchor. The conformance build substitutes a populated version of this type.
type overrides struct{}

func (overrides) root() []byte { return nil }
