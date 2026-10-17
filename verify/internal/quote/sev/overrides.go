//go:build !tinfoil_conformance

package sev

// overrides carries no trust-anchor replacement in a production build.
type overrides struct{}

func (overrides) root() []byte { return nil }
