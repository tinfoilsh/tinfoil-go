//go:build tinfoil_conformance

package quote

import (
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/quote/sev"
	"github.com/tinfoilsh/tinfoil-go/verifier/quote/tdx"
)

// overrides carries the conformance build's replacements for the verification
// clock and the vendor trust anchors, translated down to whichever platform
// the document's evidence selects. See the setters below.
type overrides struct {
	now   time.Time
	amd   []byte
	intel []byte
}

func (o overrides) sev() *sev.Options {
	opts := &sev.Options{}
	opts.DangerousTestOnlySetClock(o.now)
	opts.DangerousTestOnlySetRoot(o.amd)
	return opts
}

func (o overrides) tdx() *tdx.Options {
	opts := &tdx.Options{}
	opts.DangerousTestOnlySetClock(o.now)
	opts.DangerousTestOnlySetRoot(o.intel)
	return opts
}

// DangerousTestOnlySetClock pins the instant certificate and CRL validity
// windows are evaluated at, so the conformance harness can replay a frozen
// document at its capture time. A rewound clock accepts expired certificates
// and superseded CRLs, which is why this exists only in the conformance build.
func (o *Options) DangerousTestOnlySetClock(t time.Time) { o.overrides.now = t }

// DangerousTestOnlySetRoots replaces the embedded vendor anchors, so the
// conformance harness can authenticate synthetic evidence. A supplied anchor
// destroys the guarantee that evidence chains to AMD or Intel, which is why
// this exists only in the conformance build. Nil entries keep the embedded
// anchor for that platform.
func (o *Options) DangerousTestOnlySetRoots(amdRootPEM, intelRootPEM []byte) {
	o.overrides.amd, o.overrides.intel = amdRootPEM, intelRootPEM
}
