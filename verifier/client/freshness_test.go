package client

import (
	"cmp"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
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
	defaults, err := NewSecureClient("enclave.example", "org/repo", nil)
	require.NoError(t, err)
	require.Equal(t, 7*24*time.Hour, defaults.options.FreshnessMaxAge)
	for _, maxAge := range []time.Duration{-time.Nanosecond, -time.Hour} {
		opts := VerificationOptions{FreshnessMaxAge: maxAge}
		s, err := NewSecureClient("enclave.example", "org/repo", &opts)
		require.Nil(t, s)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		s, err = NewDefaultClient(&opts)
		require.Nil(t, s)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		_, err = VerifyDocumentV3(nil, nil, "org/repo", &opts)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
	}
	for _, maxAge := range []time.Duration{0, 24 * time.Hour, 30 * 24 * time.Hour} {
		opts := VerificationOptions{FreshnessMaxAge: maxAge, PinnedRegisters: &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: measurement.RTMR3_ZERO}}}
		s, err := NewSecureClient(fallbackEnclave, defaultRouterRepo, &opts)
		require.NoError(t, err)
		require.Equal(t, cmp.Or(maxAge, 7*24*time.Hour), s.options.FreshnessMaxAge)
		require.Equal(t, opts.PinnedRegisters, s.options.PinnedRegisters)
	}
}

func TestLiveVerifyFreshnessExpiration(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	host, repo := os.Getenv(enclaveEnvVar), os.Getenv(repoEnvVar)
	nonce, err := envelope.RandomNonce()
	require.NoError(t, err)
	raw, err := envelope.Fetch(host, nonce)
	require.NoError(t, err)
	verified, err := VerifyDocumentV3(raw, nonce, repo, nil)
	require.NoError(t, err)
	const maxAge = 30 * 24 * time.Hour
	for _, age := range []time.Duration{0, maxAge} {
		opts := VerificationOptions{FreshnessMaxAge: age, PinnedRegisters: verified.EnclaveMeasurement}
		custom, err := VerifyDocumentV3(raw, nonce, repo, &opts)
		require.NoError(t, err)
		require.Equal(t, verified.FreshnessExpiresAt.Add(cmp.Or(age, provenance.MaxFreshnessAge)-provenance.MaxFreshnessAge), custom.FreshnessExpiresAt)
		optionsJSON, err := json.Marshal(opts)
		require.NoError(t, err)
		parsed, err := ParseVerificationOptionsJSON(string(optionsJSON))
		require.NoError(t, err)
		resultJSON, err := VerifyDocumentV3JSON(raw, nonce, repo, parsed)
		require.NoError(t, err)
		var mobileResult VerifiedDocumentV3
		require.NoError(t, json.Unmarshal([]byte(resultJSON), &mobileResult))
		custom.FreshnessExpiresAt, mobileResult.FreshnessExpiresAt = custom.FreshnessExpiresAt.UTC(), mobileResult.FreshnessExpiresAt.UTC()
		require.Equal(t, *custom, mobileResult, "mobile callers receive the same keys, measurements, and expiry")
	}
	badPins := cloneMeasurement(verified.EnclaveMeasurement)
	badPins.Registers[0] = strings.Repeat("ab", 48)
	require.NotEqual(t, verified.EnclaveMeasurement.Registers[0], badPins.Registers[0])
	_, err = VerifyDocumentV3(raw, nonce, repo, &VerificationOptions{PinnedRegisters: badPins})
	var attestation *AttestationError
	require.ErrorAs(t, err, &attestation)
	_, err = NewDefaultClient(&VerificationOptions{PinnedRegisters: badPins, FreshnessMaxAge: maxAge})
	require.ErrorAs(t, err, &attestation)
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
		loggedAt, err := provenance.AuthenticateFreshness(collateral.SigstoreBundle, artifact, time.Now(), 0)
		require.NoError(t, err)
		_, err = provenance.AuthenticateFreshness(collateral.SigstoreBundle, artifact, loggedAt.Add(8*24*time.Hour), 0)
		require.ErrorContains(t, err, "stale")
		_, err = provenance.AuthenticateFreshness(collateral.SigstoreBundle, artifact, loggedAt.Add(8*24*time.Hour), maxAge)
		require.NoError(t, err)
		_, err = provenance.AuthenticateFreshness(collateral.SigstoreBundle, artifact, loggedAt.Add(7*24*time.Hour), 0)
		require.NoError(t, err)
		_, err = provenance.AuthenticateFreshness(collateral.SigstoreBundle, artifact, loggedAt.Add(7*24*time.Hour+time.Nanosecond), 0)
		require.ErrorContains(t, err, "stale")
		expiresAt := loggedAt.Add(provenance.MaxFreshnessAge)
		require.False(t, verified.FreshnessExpiresAt.After(expiresAt), "%s witness expires before public deadline", id)
		matched = matched || verified.FreshnessExpiresAt.Equal(expiresAt)
	}
	require.True(t, matched, "public deadline must equal one of the authenticated witness expirations")
}
