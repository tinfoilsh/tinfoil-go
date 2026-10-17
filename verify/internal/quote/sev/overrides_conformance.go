//go:build tinfoil_conformance

package sev

// overrides carries the conformance build's replacement for the AMD trust anchor. See the setters below.
type overrides struct {
	rootPEM []byte
}

func (o overrides) root() []byte { return o.rootPEM }

// DangerousTestOnlySetRoot replaces the embedded per-product ASK+ARK anchor
// with the supplied AMD KDS cert_chain, so the conformance harness can
// authenticate synthetic reports. A supplied anchor destroys the guarantee
// that evidence chains to AMD, which is why this exists only in the
// conformance build. A nil rootPEM keeps the embedded anchor.
func (o *Options) DangerousTestOnlySetRoot(rootPEM []byte) { o.overrides.rootPEM = rootPEM }
