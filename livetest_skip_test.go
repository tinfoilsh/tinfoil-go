package tinfoil

import (
	"strings"
	"testing"
)

// skipIfEnclaveNotV3 skips a live-enclave test while the fleet still serves a
// pre-v3 attestation document, which the v3 verifier rejects at parse time.
func skipIfEnclaveNotV3(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), "unknown object member") {
		t.Skipf("live enclave does not serve a v3 attestation document yet: %v", err)
	}
}
