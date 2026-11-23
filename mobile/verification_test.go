package mobile

import (
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func sampleFields() verifytest.Fields {
	return verifytest.Fields{
		ConfigRepo:         "tinfoilsh/confidential-model-router",
		CodeDigest:         "abc123",
		CodeTag:            "v1.2.3",
		CodeMeasurement:    measurement.ExpectedTDX{RTMR1: &measurement.Register{0xbb}, RTMR2: &measurement.Register{0xcc}},
		EnclaveMeasurement: measurement.TDX{MRTD: measurement.Register{0xdd}, RTMR1: measurement.Register{0xbb}, RTMR2: measurement.Register{0xcc}},
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: "tls", Format: document.KeySPKIFPSHA256V1Format, Data: "deadbeef"},
			{ID: "hpke", Format: document.KeyX25519HPKEV1Format, Data: "cafebabe"},
		},
		FreshnessExpiresAt: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC),
	}
}

func sampleVerification() *verify.VerifiedFacts {
	return verifytest.New(sampleFields())
}

// encodeResult encodes the result of a verification that proved facts, and
// returns it decoded as plain JSON.
func encodeResult(t *testing.T, facts *verify.VerifiedFacts) map[string]any {
	t.Helper()
	report := verifytest.Passed(facts)
	report.Metadata.VerifiedAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	encoded, err := encode(toResultJSON(report, nil))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(encoded), &got))
	return got
}

// encodeFacts returns the verified facts of encodeResult.
func encodeFacts(t *testing.T, facts *verify.VerifiedFacts) map[string]any {
	t.Helper()
	return encodeResult(t, facts)["report"].(map[string]any)["verified_facts"].(map[string]any)
}

// Lifting the channel keys out of crypto_material by ID and format is the only
// real work this mapping does: binding a connection is what a caller has a
// verification for, and it should not have to repeat the lookup.
func TestVerificationLiftsChannelKeys(t *testing.T) {
	got := encodeFacts(t, sampleVerification())
	assert.Equal(t, "deadbeef", got["tls_public_key_fp"])
	assert.Equal(t, "cafebabe", got["hpke_public_key"])
	assert.Len(t, got["crypto_material"], 2, "lifted keys are still listed in full")
}

// A TLS-only enclave endorses no HPKE key. That has to be an absent field
// rather than a failed mapping, or such an enclave could not be used at all.
func TestVerificationOmitsMissingHPKE(t *testing.T) {
	f := sampleFields()
	f.CryptoMaterial = f.CryptoMaterial[:1]

	got := encodeFacts(t, verifytest.New(f))
	assert.Equal(t, "deadbeef", got["tls_public_key_fp"])
	assert.NotContains(t, got, "hpke_public_key")
}

// time.Time cannot cross the FFI boundary, so the deadline a caller must honour
// is formatted here and parsed back on the other side.
func TestVerificationFormatsFreshnessDeadline(t *testing.T) {
	got := encodeFacts(t, sampleVerification())
	parsed, err := time.Parse(time.RFC3339Nano, got["freshness_expires_at"].(string))
	require.NoError(t, err)
	assert.True(t, parsed.Equal(sampleVerification().FreshnessExpiresAt()))
}

// The appraisal time comes from the report's metadata. The host and the
// verifying SDK are the caller's: nothing attests either.
func TestVerificationKeepsAppraisalTimeOnly(t *testing.T) {
	result := encodeResult(t, sampleVerification())
	assert.Equal(t, float64(VerificationSchemaVersion), result["schema_version"])
	assert.NotContains(t, result, "error")
	report := result["report"].(map[string]any)
	assert.Equal(t, map[string]any{"verified_at": "2026-09-26T12:00:00Z"}, report["metadata"])
	assert.NotContains(t, report, "partial_facts")
	got := report["verified_facts"].(map[string]any)
	assert.Equal(t, "tinfoilsh/confidential-model-router", got["config_repo"])
	assert.NotContains(t, got, "enclave_host")
	assert.NotContains(t, got, "verifier")
	assert.NotContains(t, got, "verified_at")
	steps := report["steps"].([]any)
	require.Len(t, steps, 4)
	for i, layer := range []string{"envelope", "provenance", "quote", "policy"} {
		assert.Equal(t, map[string]any{"layer": layer, "status": "passed"}, steps[i])
	}
}

// A rejection is a result too: the report, with the failed step and the
// partial facts, and the error in the bridge's message format.
func TestRejectionResult(t *testing.T) {
	launch := measurement.Register{0xaa}
	rejected := verifytest.Rejected("report signature is invalid")
	rejected.Report.PartialFacts = &verify.PartialFacts{
		Expected: &verify.ExpectedFacts{
			ConfigRepo:      "tinfoilsh/repo",
			Artifact:        verify.ArtifactVerification{Source: verify.SourceEndorsement, Repo: "tinfoilsh/repo", Digest: "d0"},
			CodeMeasurement: measurement.ExpectedSEVSNP{Launch: &launch},
		},
		Measured: &verify.MeasuredFacts{TLSPublicKeyFP: "aa", HPKEPublicKeyFP: "bb"},
	}
	rejected.Report.Metadata.VerifiedAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	encoded, err := encode(toResultJSON(nil, rejected))
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal([]byte(encoded), &got))
	message := VerificationErrorPrefix + "quote: report signature is invalid"
	assert.Equal(t, map[string]any{"layer": "quote", "message": message}, got["error"])
	report := got["report"].(map[string]any)
	assert.NotContains(t, report, "verified_facts")
	assert.Equal(t, []any{
		map[string]any{"layer": "envelope", "status": "passed"},
		map[string]any{"layer": "provenance", "status": "passed"},
		map[string]any{"layer": "quote", "status": "failed", "message": "report signature is invalid"},
		map[string]any{"layer": "policy", "status": "not_run"},
	}, report["steps"])
	assert.Equal(t, map[string]any{
		"expected": map[string]any{
			"config_repo": "tinfoilsh/repo",
			"artifact":    map[string]any{"source": "endorsement", "repo": "tinfoilsh/repo", "digest": "d0"},
			"code_measurement": map[string]any{
				"type": "https://tinfoil.sh/predicate/sev-snp-guest/v2", "registers": []any{launch.String()},
			},
		},
		"measured": map[string]any{"tls_public_key_fp": "aa", "hpke_public_key_fp": "bb"},
	}, report["partial_facts"])
}

// Measurements keep the contract's {type, registers} shape, with "" for a
// register the release leaves to the platform.
func TestVerificationMeasurements(t *testing.T) {
	got := encodeFacts(t, sampleVerification())
	rtmr1, rtmr2 := measurement.Register{0xbb}.String(), measurement.Register{0xcc}.String()
	assert.Equal(t, map[string]any{
		"type":      "https://tinfoil.sh/predicate/tdx-guest/v2",
		"registers": []any{"", "", rtmr1, rtmr2, ""},
	}, got["code_measurement"])
	assert.Equal(t, map[string]any{
		"type":      "https://tinfoil.sh/predicate/tdx-guest/v2",
		"registers": []any{measurement.Register{0xdd}.String(), measurement.Register{}.String(), rtmr1, rtmr2, measurement.Register{}.String()},
	}, got["enclave_measurement"])
}

// A code-release verification has no config, runtime or platform.
func TestVerificationOmitsConfigFactsForCodeRelease(t *testing.T) {
	got := encodeFacts(t, sampleVerification())
	assert.NotContains(t, got, "config")
	assert.NotContains(t, got, "runtime")
	assert.NotContains(t, got, "platform")
}

// A config-based verification reports what it accepted for each component and
// why, with absent facts omitted rather than written as zero values.
func TestVerificationConfigFacts(t *testing.T) {
	approved := time.Date(2026, 9, 20, 8, 0, 0, 500, time.UTC)
	f := sampleFields()
	f.Config = &verify.ConfigVerification{
		Source: verify.SourceEndorsement, Name: "/org/project/v1", Digest: "c0",
		Reference: "sha256:c0", SigningKeyHint: "hint", ApprovalTime: approved,
		RegistryID: "registry", SignatureTime: approved.Add(time.Minute),
	}
	f.Runtime = &verify.ArtifactVerification{
		Source: verify.SourceEndorsement, Repo: "tinfoilsh/cvmimage", Tag: "v0.15.0",
		Digest: "r0", Name: "runtime", Commit: "abc", ApprovalTime: approved,
	}
	f.Platform = &verify.ArtifactVerification{Source: verify.SourceEmbedded, Digest: "p0"}

	got := encodeFacts(t, verifytest.New(f))
	assert.Equal(t, map[string]any{
		"source": "endorsement", "name": "/org/project/v1", "digest": "c0",
		"reference": "sha256:c0", "signing_key_hint": "hint",
		"approval_time": "2026-09-20T08:00:00.0000005Z", "registry_id": "registry",
		"signature_time": "2026-09-20T08:01:00.0000005Z",
	}, got["config"])
	assert.Equal(t, map[string]any{
		"source": "endorsement", "repo": "tinfoilsh/cvmimage", "tag": "v0.15.0",
		"digest": "r0", "name": "runtime", "commit": "abc",
		"approval_time": "2026-09-20T08:00:00.0000005Z",
	}, got["runtime"])
	assert.Equal(t, map[string]any{"source": "embedded", "digest": "p0"}, got["platform"])
}

// A config a ConfigAuthorizer approved has only its source and digest.
func TestVerificationPolicyConfig(t *testing.T) {
	f := sampleFields()
	f.Config = &verify.ConfigVerification{Source: verify.SourcePolicy, Digest: "c0"}

	got := encodeFacts(t, verifytest.New(f))
	assert.Equal(t, map[string]any{"source": "policy", "digest": "c0"}, got["config"])
}
