//go:build tinfoil_conformance

package tdx

import "time"

// overrides carries the conformance build's replacements for the verification
// clock and the Intel SGX root. See the setters below.
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

// DangerousTestOnlySetRoot replaces the embedded Intel SGX root, so the
// conformance harness can authenticate synthetic quotes. A supplied root
// destroys the guarantee that evidence chains to Intel, which is why this
// exists only in the conformance build. A nil rootPEM keeps the embedded root.
func (o *Options) DangerousTestOnlySetRoot(rootPEM []byte) { o.overrides.rootPEM = rootPEM }
