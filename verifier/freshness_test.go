package verifier

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verifier/document"
	"github.com/tinfoilsh/tinfoil-go/verifier/internal/provenance"
)

func TestFreshnessExpiration(t *testing.T) {
	issuedAt := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	later := issuedAt.Add(time.Hour)
	for _, tt := range []struct {
		name                string
		codeWitnessedAt     time.Time
		platformWitnessedAt time.Time
	}{
		{"code expires first", issuedAt, later},
		{"platform expires first", later, issuedAt},
		{"same issuance time", issuedAt, issuedAt},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, maxAge := range []time.Duration{24 * time.Hour, provenance.MaxFreshnessAge, 30 * 24 * time.Hour} {
				require.Equal(t, issuedAt.Add(maxAge), freshnessExpiration(tt.codeWitnessedAt, tt.platformWitnessedAt, maxAge))
			}
		})
	}
}

func TestLiveIgnoreFreshness(t *testing.T) {
	const enclaveEnvVar, repoEnvVar = "TINFOIL_ENCLAVE", "TINFOIL_REPO"
	const expiredMaxAge = time.Nanosecond
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	repo := os.Getenv(repoEnvVar)
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	raw, err := document.Fetch(os.Getenv(enclaveEnvVar), nonce)
	require.NoError(t, err)
	defaults, err := New()
	require.NoError(t, err)
	want, err := defaults.VerifyV3(raw, nonce, repo)
	require.NoError(t, err)
	require.False(t, want.FreshnessExpiresAt.IsZero())
	want.FreshnessExpiresAt = time.Time{}
	ignored, err := New(WithFreshnessMaxAge(expiredMaxAge), WithIgnoreFreshness())
	require.NoError(t, err)

	changeCollateral := func(format string, remove bool) func(*document.Document) {
		return func(doc *document.Document) {
			doc.Collateral = slices.DeleteFunc(doc.Collateral, func(entry document.CollateralEntry) bool {
				return remove && entry.Format == format
			})
			for i := range doc.Collateral {
				if doc.Collateral[i].Format == format {
					doc.Collateral[i].Data = []byte(`{"sigstore_bundle":{}}`)
				}
			}
		}
	}
	for _, tt := range []struct {
		name      string
		mutate    func(*document.Document)
		maxAge    time.Duration
		wantError string
		accept    bool
	}{
		{"expired witnesses", nil, expiredMaxAge, "stale", true},
		{"missing witnesses", changeCollateral(document.CollateralSigstoreFreshnessV1Format, true), 0, "code-freshness", true},
		{"invalid witnesses", changeCollateral(document.CollateralSigstoreFreshnessV1Format, false), 0, "verifying code freshness", true},
		{"invalid code provenance", changeCollateral(document.CollateralSigstoreCodeV1Format, false), 0, "verifying code measurement", false},
		{"invalid platform provenance", changeCollateral(document.CollateralSigstorePlatformV1Format, false), 0, "verifying platform endorsements", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := document.Parse(raw)
			require.NoError(t, err)
			if tt.mutate != nil {
				tt.mutate(doc)
			}
			modified, err := json.Marshal(doc)
			require.NoError(t, err)
			bounded, err := New(WithFreshnessMaxAge(tt.maxAge))
			require.NoError(t, err)
			_, err = bounded.VerifyV3(modified, nonce, repo)
			require.ErrorContains(t, err, tt.wantError)
			got, err := ignored.VerifyV3(modified, nonce, repo)
			if !tt.accept {
				require.ErrorContains(t, err, tt.wantError)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}

	wrongNonce := slices.Clone(nonce)
	wrongNonce[0] ^= 1
	_, err = ignored.VerifyV3(raw, wrongNonce, repo)
	require.ErrorContains(t, err, "challenge nonce does not match")
	doc, err := document.Parse(raw)
	require.NoError(t, err)
	doc.CPUEvidence.ReportBase64 = base64.StdEncoding.EncodeToString([]byte("invalid quote"))
	modified, err := json.Marshal(doc)
	require.NoError(t, err)
	got, err := ignored.VerifyV3(modified, nonce, repo)
	require.Error(t, err)
	require.Nil(t, got)
}
