package attestation

import (
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
)

// TestEnforceRequiredPlatformInfoTSME guards the SPEC §3.7 TSME requirement.
// go-sev-guest validates TSME with allowlist semantics (it only rejects a report
// that HAS TSME when the policy disallows it), so a TSME-off report passes
// validate.SnpAttestation even with Options.PlatformInfo.TSMEEnabled=true.
// enforceRequiredPlatformInfo closes that gap; this test pins the behavior so it
// stays consistent with tinfoil-python/-rs/-js.
func TestEnforceRequiredPlatformInfoTSME(t *testing.T) {
	const (
		smtBit  = uint64(1 << 0)
		tsmeBit = uint64(1 << 1)
	)
	required := &abi.SnpPlatformInfo{TSMEEnabled: true}

	// TSME off -> rejected.
	off := &sevsnp.Report{PlatformInfo: smtBit}
	if err := enforceRequiredPlatformInfo(off, required); err == nil {
		t.Fatal("expected a TSME-off report to be rejected when TSME is required")
	}

	// TSME on -> accepted.
	on := &sevsnp.Report{PlatformInfo: smtBit | tsmeBit}
	if err := enforceRequiredPlatformInfo(on, required); err != nil {
		t.Fatalf("expected a TSME-on report to pass, got: %v", err)
	}

	// No policy -> no-op.
	if err := enforceRequiredPlatformInfo(off, nil); err != nil {
		t.Fatalf("expected nil required policy to be a no-op, got: %v", err)
	}
}
