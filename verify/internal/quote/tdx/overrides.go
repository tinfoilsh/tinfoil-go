//go:build !tinfoil_conformance

package tdx

// overrides carries nothing in a production build: the Intel SGX root cannot
// be replaced, so a shipped binary cannot be made to trust a supplied root.
// The conformance build substitutes a populated version of this type.
type overrides struct{}

func (overrides) root() []byte { return nil }
