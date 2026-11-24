package mobile

import (
	"encoding/json/jsontext"
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

// decodedResult is the result JSON as a Swift or Kotlin caller decodes it,
// with the parts of the report that these tests check.
type decodedResult struct {
	SchemaVersion int `json:"schema_version"`
	Report        struct {
		SchemaVersion int `json:"schema_version"`
		Steps         []struct {
			Layer   string `json:"layer"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"steps"`
		VerifiedFacts *struct {
			ConfigRepo     string                        `json:"config_repo"`
			CodeDigest     string                        `json:"code_digest"`
			CryptoMaterial []document.CryptoMaterialItem `json:"crypto_material"`
		} `json:"verified_facts"`
		PartialFacts *struct {
			Expected jsontext.Value `json:"expected"`
			Measured jsontext.Value `json:"measured"`
		} `json:"partial_facts"`
	} `json:"report"`
	Error *errorJSON `json:"error"`
}

func decodeResult(t *testing.T, payload string) decodedResult {
	t.Helper()
	var got decodedResult
	require.NoError(t, json.Unmarshal([]byte(payload), &got))
	return got
}

// key returns the data of the verified crypto_material item with id and
// format, as a Swift or Kotlin caller looks up a channel key.
func (r decodedResult) key(id, format string) string {
	if r.Report.VerifiedFacts == nil {
		return ""
	}
	data, _ := verify.CryptoMaterialData(r.Report.VerifiedFacts.CryptoMaterial, id, format)
	return data
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

// The bridge writes the report unchanged in the SDKs' common JSON form,
// built by the same encoder as Go's own json.Marshal of a report.
func TestResultWrapsTheCommonReportForm(t *testing.T) {
	report := verifytest.Passed(sampleVerification())
	report.Metadata.VerifiedAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	encoded, err := encode(toResultJSON(report, nil))
	require.NoError(t, err)
	var result struct {
		SchemaVersion int            `json:"schema_version"`
		Report        jsontext.Value `json:"report"`
		Error         jsontext.Value `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(encoded), &result))
	assert.Equal(t, VerificationSchemaVersion, result.SchemaVersion)
	assert.Nil(t, result.Error)

	want, err := json.Marshal(report)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(result.Report))
}

// The channel keys are in crypto_material only: a caller looks them up by ID
// and format there, and the result carries no lifted copies.
func TestVerificationKeysAreInCryptoMaterialOnly(t *testing.T) {
	got := encodeResult(t, sampleVerification())["report"].(map[string]any)["verified_facts"].(map[string]any)
	assert.NotContains(t, got, "tls_public_key_fp")
	assert.NotContains(t, got, "hpke_public_key")
	assert.Equal(t, []any{
		map[string]any{"id": "tls", "format": document.KeySPKIFPSHA256V1Format, "data": "deadbeef"},
		map[string]any{"id": "hpke", "format": document.KeyX25519HPKEV1Format, "data": "cafebabe"},
	}, got["crypto_material"])
}

// The appraisal time comes from the report's metadata. The host and the
// verifying SDK are the caller's: nothing attests either.
func TestVerificationKeepsAppraisalTimeOnly(t *testing.T) {
	result := encodeResult(t, sampleVerification())
	assert.Equal(t, float64(VerificationSchemaVersion), result["schema_version"])
	assert.NotContains(t, result, "error")
	report := result["report"].(map[string]any)
	assert.Equal(t, float64(verify.ReportSchemaVersion), report["schema_version"])
	assert.Equal(t, map[string]any{"verified_at": "2026-09-26T12:00:00Z"}, report["metadata"])
	assert.NotContains(t, report, "partial_facts")
	got := report["verified_facts"].(map[string]any)
	assert.Equal(t, "tinfoilsh/confidential-model-router", got["config_repo"])
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
			"config_repo":      "tinfoilsh/repo",
			"artifact":         map[string]any{"source": "endorsement", "repo": "tinfoilsh/repo", "digest": "d0"},
			"code_measurement": map[string]any{"platform": "sev-snp", "launch": launch.String()},
		},
		"measured": map[string]any{"tls_public_key_fp": "aa", "hpke_public_key_fp": "bb"},
	}, report["partial_facts"])
	assert.Equal(t, map[string]any{"verified_at": "2026-09-26T12:00:00Z"}, report["metadata"])
}
