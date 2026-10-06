package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
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
			for _, maxAge := range []time.Duration{24 * time.Hour, endorsement.MaxFreshnessAge, 30 * 24 * time.Hour} {
				require.Equal(t, issuedAt.Add(maxAge), freshnessExpiration(maxAge, tt.codeWitnessedAt, tt.platformWitnessedAt))
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
	raw, err := fetch.Document(t.Context(), os.Getenv(enclaveEnvVar), "", nonce)
	require.NoError(t, err)
	defaults, err := NewVerifier()
	require.NoError(t, err)
	want, err := defaults.VerifyV3(raw, nonce, repo)
	require.NoError(t, err)
	require.False(t, want.FreshnessExpiresAt.IsZero())
	want.FreshnessExpiresAt = time.Time{}
	want.Metadata = VerificationMetadata{}
	ignored, err := NewVerifier(WithFreshnessMaxAge(expiredMaxAge), WithIgnoreFreshness())
	require.NoError(t, err)

	changeCollateral := func(format string, remove bool) func(map[string]any) {
		return func(doc map[string]any) {
			var kept []any
			for _, e := range doc["collateral"].([]any) {
				entry := e.(map[string]any)
				if entry["format"] == format {
					if remove {
						continue
					}
					// Only the bundle is invalidated; the entry keeps the
					// digest and other fields Parse requires.
					entry["data"].(map[string]any)["sigstore_bundle"] = map[string]any{}
				}
				kept = append(kept, entry)
			}
			doc["collateral"] = kept
		}
	}
	for _, tt := range []struct {
		name      string
		mutate    func(map[string]any)
		maxAge    time.Duration
		wantError string
		accept    bool
	}{
		{"expired witnesses", nil, expiredMaxAge, "stale", true},
		{"missing witnesses", changeCollateral(collateral.SigstoreFreshnessV1Format, true), 0, "code-freshness", true},
		{"invalid witnesses", changeCollateral(collateral.SigstoreFreshnessV1Format, false), 0, "verifying code freshness", true},
		{"invalid code provenance", changeCollateral(collateral.SigstoreCodeV1Format, false), 0, "verifying code measurement", false},
		{"invalid platform provenance", changeCollateral(collateral.SigstorePlatformV1Format, false), 0, "verifying platform endorsements", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			modified := raw
			if tt.mutate != nil {
				modified = editDocument(t, raw, tt.mutate)
			}
			bounded, err := NewVerifier(WithFreshnessMaxAge(tt.maxAge))
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
			require.False(t, got.Metadata.VerifiedAt.IsZero())
			got.Metadata = VerificationMetadata{}
			require.Equal(t, want, got)
		})
	}

	wrongNonce := slices.Clone(nonce)
	wrongNonce[0] ^= 1
	_, err = ignored.VerifyV3(raw, wrongNonce, repo)
	require.ErrorContains(t, err, "challenge nonce does not match")
	modified := editDocument(t, raw, func(doc map[string]any) {
		doc["cpu_evidence"].(map[string]any)["report_base64"] = base64.StdEncoding.EncodeToString([]byte("invalid quote"))
	})
	got, err := ignored.VerifyV3(modified, nonce, repo)
	require.Error(t, err)
	require.Nil(t, got)
}

// editDocument decodes a serialized document as plain JSON, applies edit, and
// re-encodes it. Numbers stay exact and the endorsed sections, which travel as
// base64 strings, keep their bytes.
func editDocument(t *testing.T, raw []byte, edit func(map[string]any)) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	require.NoError(t, dec.Decode(&doc))
	edit(doc)
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

func TestLiveFreshnessWitnessExpiration(t *testing.T) {
	const enclaveEnvVar, repoEnvVar = "TINFOIL_ENCLAVE", "TINFOIL_REPO"
	const maxAge = 30 * 24 * time.Hour
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	repo := os.Getenv(repoEnvVar)
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	raw, err := fetch.Document(t.Context(), os.Getenv(enclaveEnvVar), "", nonce)
	require.NoError(t, err)
	verifier, err := NewVerifier()
	require.NoError(t, err)
	verified, err := verifier.VerifyV3(raw, nonce, repo)
	require.NoError(t, err)
	doc, err := document.Parse(raw, nonce)
	require.NoError(t, err)
	codeRef, err := doc.SigstoreCode()
	require.NoError(t, err)
	provClient, err := endorsement.NewDefaultClient()
	require.NoError(t, err)
	code, err := provClient.AuthenticateCode(codeRef.Bundle, repo, codeRef.Tag, codeRef.Digest)
	require.NoError(t, err)
	platformRef, err := doc.SigstorePlatform()
	require.NoError(t, err)
	platform, err := provClient.AuthenticatePlatformEndorsements(platformRef.Bundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	require.NoError(t, err)
	matched := false
	for id, artifact := range map[string]*endorsement.AuthenticatedArtifact{
		collateral.FreshnessIDCode:     &code.AuthenticatedArtifact,
		collateral.FreshnessIDPlatform: &platform.AuthenticatedArtifact,
	} {
		witness, err := doc.Freshness(id)
		require.NoError(t, err)
		loggedAt, err := provClient.AuthenticateFreshness(witness.Bundle, artifact, time.Now(), 0)
		require.NoError(t, err)
		_, err = provClient.AuthenticateFreshness(witness.Bundle, artifact, loggedAt.Add(8*24*time.Hour), 0)
		require.ErrorContains(t, err, "stale")
		_, err = provClient.AuthenticateFreshness(witness.Bundle, artifact, loggedAt.Add(8*24*time.Hour), maxAge)
		require.NoError(t, err)
		_, err = provClient.AuthenticateFreshness(witness.Bundle, artifact, loggedAt.Add(7*24*time.Hour), 0)
		require.NoError(t, err)
		_, err = provClient.AuthenticateFreshness(witness.Bundle, artifact, loggedAt.Add(7*24*time.Hour+time.Nanosecond), 0)
		require.ErrorContains(t, err, "stale")
		expiresAt := loggedAt.Add(endorsement.MaxFreshnessAge)
		require.False(t, verified.FreshnessExpiresAt.After(expiresAt), "%s witness expires before public deadline", id)
		matched = matched || verified.FreshnessExpiresAt.Equal(expiresAt)
	}
	require.True(t, matched, "public deadline must equal one of the authenticated witness expirations")
}
