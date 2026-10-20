//go:build tinfoil_conformance

package document

// DangerousTestOnlyDecode applies Parse's structural rules without checking
// the challenge against a nonce, so the conformance harness can drive the
// provenance and quote stages in isolation. The result is unbound: it has no
// expected REPORT_DATA and quote.Assemble rejects it. Skipping the nonce
// binding would let a replayed document through, which is why this exists
// only in the conformance build.
func DangerousTestOnlyDecode(docBytes []byte) (*Document, error) {
	return decode(docBytes)
}
