//go:build tinfoil_conformance

package sev

import "time"

// overrides carries the conformance build's replacements for the verification
// clock and the AMD trust anchor. See the setters below.
type overrides struct {
	now     time.Time
	rootPEM []byte
}

func (o overrides) clock() time.Time { return o.now }
func (o overrides) root() []byte     { return o.rootPEM }

// DangerousTestOnlySetClock pins the instant certificate and CRL validity
// windows are evaluated at, so the conformance harness can replay a frozen
// document at its capture time. A rewound clock accepts expired certificates
// and superseded CRLs, which is why this exists only in the conformance build.
func (o *Options) DangerousTestOnlySetClock(t time.Time) { o.overrides.now = t }

// DangerousTestOnlySetRoot replaces the embedded per-product ASK+ARK anchor
// with the supplied AMD KDS cert_chain, so the conformance harness can
// authenticate synthetic reports. A supplied anchor destroys the guarantee
// that evidence chains to AMD, which is why this exists only in the
// conformance build. A nil rootPEM keeps the embedded anchor.
func (o *Options) DangerousTestOnlySetRoot(rootPEM []byte) { o.overrides.rootPEM = rootPEM }
