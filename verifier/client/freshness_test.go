package client

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

func TestFreshnessExpiration(t *testing.T) {
	issuedAt := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	later := issuedAt.Add(time.Hour)
	want := issuedAt.Add(provenance.MaxFreshnessAge)
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
			require.Equal(t, want, freshnessExpiration(tt.codeWitnessedAt, tt.platformWitnessedAt))
		})
	}
}

// Like TestVerify, this is opt-in. It also checks that the public result carries
// the earlier expiration from the authenticated witnesses.
func TestVerifyV3FreshnessExpiration(t *testing.T) {
	host, repo := os.Getenv("TINFOIL_ENCLAVE"), os.Getenv("TINFOIL_REPO")
	if host == "" || repo == "" {
		t.Skip("TINFOIL_ENCLAVE or TINFOIL_REPO not set")
	}
	nonce, err := envelope.RandomNonce()
	require.NoError(t, err)
	raw, err := envelope.Fetch(host, nonce)
	require.NoError(t, err)
	verified, err := VerifyDocumentV3(raw, nonce, repo, nil)
	require.NoError(t, err)
	doc, err := envelope.Parse(raw)
	require.NoError(t, err)
	codeRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstoreCodeV1Format)
	require.NoError(t, err)
	code, err := provenance.AuthenticateCode(codeRef.SigstoreBundle, repo, codeRef.Tag, codeRef.Digest)
	require.NoError(t, err)
	platformRef, err := doc.ReferenceValuesCollateral(envelope.CollateralSigstorePlatformV1Format)
	require.NoError(t, err)
	platform, err := provenance.AuthenticatePlatformEndorsements(platformRef.SigstoreBundle, platformRef.Repo, platformRef.Tag, platformRef.Digest)
	require.NoError(t, err)
	matched := false
	for id, artifact := range map[string]*provenance.AuthenticatedArtifact{
		envelope.FreshnessCollateralIDCode:     &code.AuthenticatedArtifact,
		envelope.FreshnessCollateralIDPlatform: &platform.AuthenticatedArtifact,
	} {
		collateral, err := doc.FreshnessCollateral(id)
		require.NoError(t, err)
		loggedAt, err := provenance.AuthenticateFreshness(collateral.SigstoreBundle, artifact, time.Now())
		require.NoError(t, err)
		expiresAt := loggedAt.Add(provenance.MaxFreshnessAge)
		require.False(t, verified.FreshnessExpiresAt.After(expiresAt), "%s witness expires before public deadline", id)
		matched = matched || verified.FreshnessExpiresAt.Equal(expiresAt)
	}
	require.True(t, matched, "public deadline must equal one of the authenticated witness expirations")
}
