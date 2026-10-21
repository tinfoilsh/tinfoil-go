//go:build tinfoil_conformance

package quote

import (
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/quote/tdx"
)

// overrides carries the conformance build's replacements for the vendor trust
// anchors, translated down to whichever platform the document's evidence
// selects. See the setter below.
type overrides struct {
	amd   []byte
	intel []byte
}

func (o overrides) sev() *sev.Options {
	opts := &sev.Options{}
	opts.DangerousTestOnlySetRoot(o.amd)
	return opts
}

func (o overrides) tdx() *tdx.Options {
	opts := &tdx.Options{}
	opts.DangerousTestOnlySetRoot(o.intel)
	return opts
}

// DangerousTestOnlySetRoots replaces the embedded vendor anchors, so the
// conformance harness can authenticate synthetic evidence. A supplied anchor
// destroys the guarantee that evidence chains to AMD or Intel, which is why
// this exists only in the conformance build. Nil entries keep the embedded
// anchor for that platform.
func (o *Options) DangerousTestOnlySetRoots(amdRootPEM, intelRootPEM []byte) {
	o.overrides.amd, o.overrides.intel = amdRootPEM, intelRootPEM
}
