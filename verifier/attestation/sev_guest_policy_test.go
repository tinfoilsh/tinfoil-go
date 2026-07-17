package attestation

import (
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
)

// TestEnforceGuestPolicyAllowlistMemAES256XTS guards the SPEC §3.7.2 #1
// allowlist requirement for mem_aes256_xts. go-sev-guest validates that bit with
// require semantics (`required && !policy`), so a report that ENABLES AES-256-XTS
// passes validate.SnpAttestation even when the policy doesn't allow it.
// enforceGuestPolicyAllowlist closes that gap; this test pins the behavior so it
// stays consistent with tinfoil-python/-rs/-js.
func TestEnforceGuestPolicyAllowlistMemAES256XTS(t *testing.T) {
	const (
		mboBit          = uint64(1 << 17) // reserved, MUST be 1
		memAES256XTSBit = uint64(1 << 22)
	)

	// mem_aes256_xts enabled, not allowed -> rejected.
	on := &sevsnp.Report{Policy: mboBit | memAES256XTSBit}
	if err := enforceGuestPolicyAllowlist(on, abi.SnpPolicy{}); err == nil {
		t.Fatal("expected a mem_aes256_xts-enabled report to be rejected when not allowed")
	}

	// mem_aes256_xts enabled, explicitly allowed -> accepted.
	if err := enforceGuestPolicyAllowlist(on, abi.SnpPolicy{MemAES256XTS: true}); err != nil {
		t.Fatalf("expected a mem_aes256_xts-enabled report to pass when allowed, got: %v", err)
	}

	// mem_aes256_xts off -> accepted.
	off := &sevsnp.Report{Policy: mboBit}
	if err := enforceGuestPolicyAllowlist(off, abi.SnpPolicy{}); err != nil {
		t.Fatalf("expected a mem_aes256_xts-off report to pass, got: %v", err)
	}
}
