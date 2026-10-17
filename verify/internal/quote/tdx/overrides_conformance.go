//go:build tinfoil_conformance

package tdx

// overrides carries the conformance build's replacement for the Intel SGX root. See the setters below.
type overrides struct {
	rootPEM []byte
}

func (o overrides) root() []byte { return o.rootPEM }

// DangerousTestOnlySetRoot replaces the embedded Intel SGX root, so the
// conformance harness can authenticate synthetic quotes. A supplied root
// destroys the guarantee that evidence chains to Intel, which is why this
// exists only in the conformance build. A nil rootPEM keeps the embedded root.
func (o *Options) DangerousTestOnlySetRoot(rootPEM []byte) { o.overrides.rootPEM = rootPEM }
