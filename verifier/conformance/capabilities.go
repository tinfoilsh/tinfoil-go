//go:build tinfoil_conformance

package conformance

// Capabilities is the adapter's self-description; the suite reads it to gate
// which fixtures this SDK can run. Same shape across languages.
func Capabilities() map[string]any {
	return map[string]any{
		"schema_version": "1",
		"sdk":            "tinfoil-go",
		"v3": map[string]any{
			"supported":          true,
			"stages_supported":   []string{StageVerify, StageCheckEnvelope, StageAuthenticateProvenance, StageAssemblePolicy, StageAuthenticateQuote},
			"synthetic_roots":    map[string]bool{"amd": true, "intel": true, "sigstore": true},
			"freshness_enforced": true,
		},
	}
}
