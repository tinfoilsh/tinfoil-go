package client

import (
	"cmp"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
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

func TestClientFreshnessMaxAge(t *testing.T) {
	require.Equal(t, 7*24*time.Hour, NewSecureClient("enclave.example", "org/repo").freshnessMaxAge)
	for _, maxAge := range []time.Duration{-time.Nanosecond, -time.Hour} {
		s := NewClientWithOptions("enclave.example", "org/repo", WithFreshnessMaxAge(maxAge))
		_, err := s.Verify()
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		opts := VerificationOptions{FreshnessMaxAge: maxAge}
		s, err = NewSecureClientWithOptions("enclave.example", "org/repo", opts)
		require.Nil(t, s)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		s, err = NewDefaultClientWithOptions(opts)
		require.Nil(t, s)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		_, err = VerifyDocumentV3WithOptions(nil, nil, "org/repo", opts)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) }))
	defer server.Close()
	originalURL := defaultRouterURL
	defaultRouterURL = server.URL
	t.Cleanup(func() { defaultRouterURL = originalURL })
	for _, maxAge := range []time.Duration{0, 24 * time.Hour, 30 * 24 * time.Hour} {
		opts := VerificationOptions{FreshnessMaxAge: maxAge, PinnedRegisters: &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: measurement.RTMR3_ZERO}}}
		s, err := NewDefaultClientWithOptions(opts)
		require.NoError(t, err)
		require.Equal(t, "inference.tinfoil.sh", s.Enclave())
		require.Equal(t, cmp.Or(maxAge, 7*24*time.Hour), s.freshnessMaxAge)
		require.Equal(t, opts.PinnedRegisters, s.pins)
	}
}

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
	const maxAge = 30 * 24 * time.Hour
	for _, age := range []time.Duration{0, maxAge} {
		opts := VerificationOptions{FreshnessMaxAge: age, PinnedRegisters: verified.EnclaveMeasurement}
		custom, err := VerifyDocumentV3WithOptions(raw, nonce, repo, opts)
		require.NoError(t, err)
		require.Equal(t, verified.FreshnessExpiresAt.Add(cmp.Or(age, provenance.MaxFreshnessAge)-provenance.MaxFreshnessAge), custom.FreshnessExpiresAt)
	}
	badPins := cloneMeasurement(verified.EnclaveMeasurement)
	badPins.Registers[0] = "bad"
	_, err = VerifyDocumentV3WithOptions(raw, nonce, repo, VerificationOptions{PinnedRegisters: badPins})
	require.ErrorContains(t, err, "cpu evidence")
	s, err := NewDefaultClientWithOptions(VerificationOptions{PinnedRegisters: badPins, FreshnessMaxAge: maxAge})
	require.NoError(t, err)
	_, err = s.Verify()
	require.ErrorContains(t, err, "cpu evidence")
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
		_, err = provenance.AuthenticateFreshness(collateral.SigstoreBundle, artifact, loggedAt.Add(8*24*time.Hour))
		require.ErrorContains(t, err, "stale")
		_, err = provenance.AuthenticateFreshnessWithMaxAge(collateral.SigstoreBundle, artifact, loggedAt.Add(8*24*time.Hour), maxAge)
		require.NoError(t, err)
		_, err = provenance.AuthenticateFreshnessWithMaxAge(collateral.SigstoreBundle, artifact, loggedAt.Add(7*24*time.Hour), 0)
		require.NoError(t, err)
		_, err = provenance.AuthenticateFreshnessWithMaxAge(collateral.SigstoreBundle, artifact, loggedAt.Add(7*24*time.Hour+time.Nanosecond), 0)
		require.ErrorContains(t, err, "stale")
		expiresAt := loggedAt.Add(provenance.MaxFreshnessAge)
		require.False(t, verified.FreshnessExpiresAt.After(expiresAt), "%s witness expires before public deadline", id)
		matched = matched || verified.FreshnessExpiresAt.Equal(expiresAt)
	}
	require.True(t, matched, "public deadline must equal one of the authenticated witness expirations")
}
