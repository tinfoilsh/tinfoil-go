package provenance

import (
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAuthenticatedArtifact() *AuthenticatedArtifact {
	return &AuthenticatedArtifact{
		Repo:        platformEndorsementsRepo,
		Tag:         "v0.0.4",
		Commit:      "0123456789abcdef0123456789abcdef01234567",
		SubjectName: "platform-endorsements.json",
		Digest:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func testWitness() FreshnessWitness {
	expected := testAuthenticatedArtifact()
	return FreshnessWitness{
		Format: FreshnessPredicateFormat,
		Endorses: WitnessEndorsement{
			Repo:   expected.Repo,
			Tag:    expected.Tag,
			Commit: expected.Commit,
			Subject: WitnessSubject{
				Name:   expected.SubjectName,
				Digest: "sha256:" + expected.Digest,
			},
		},
	}
}

func TestValidateWitness(t *testing.T) {
	require.NoError(t, validateWitness(testWitness(), testAuthenticatedArtifact()))

	bad := testWitness()
	bad.Endorses.Subject.Digest = "sha256:abc"
	assert.Error(t, validateWitness(bad, testAuthenticatedArtifact()))

	bad = testWitness()
	bad.Endorses.Commit = "ffffffffffffffffffffffffffffffffffffffff"
	assert.Error(t, validateWitness(bad, testAuthenticatedArtifact()))
}

func TestValidateAuthenticatedArtifact(t *testing.T) {
	require.NoError(t, validateAuthenticatedArtifact(testAuthenticatedArtifact()))

	assert.Error(t, validateAuthenticatedArtifact(nil))
	bad := *testAuthenticatedArtifact()
	bad.Tag = ""
	assert.ErrorContains(t, validateAuthenticatedArtifact(&bad), "tag is empty")
	bad = *testAuthenticatedArtifact()
	bad.Commit = "abc"
	assert.ErrorContains(t, validateAuthenticatedArtifact(&bad), "commit is malformed")
	for _, digest := range []string{"abc", "sha256:" + testAuthenticatedArtifact().Digest, "ABCDEF" + testAuthenticatedArtifact().Digest[6:]} {
		bad = *testAuthenticatedArtifact()
		bad.Digest = digest
		assert.ErrorContains(t, validateAuthenticatedArtifact(&bad), "digest is malformed")
	}
}

func TestValidateFreshnessTime(t *testing.T) {
	now := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	timestamps := []verify.TimestampVerificationResult{
		{Type: "TimestampAuthority", Timestamp: now.Add(-time.Hour)},
		{Type: "Tlog", Timestamp: now.Add(-2 * time.Hour)},
		{Type: "Tlog", Timestamp: now.Add(-3 * time.Hour)},
	}
	loggedAt, err := validateFreshnessTime(timestamps, now, MaxFreshnessAge)
	require.NoError(t, err)
	assert.Equal(t, now.Add(-3*time.Hour), loggedAt)

	_, err = validateFreshnessTime(nil, now, MaxFreshnessAge)
	assert.ErrorContains(t, err, "no verified transparency-log timestamp")

	_, err = validateFreshnessTime([]verify.TimestampVerificationResult{{Type: "TimestampAuthority", Timestamp: now.Add(-time.Hour)}}, now, MaxFreshnessAge)
	assert.ErrorContains(t, err, "no verified transparency-log timestamp")

	for _, maxAge := range []time.Duration{24 * time.Hour, MaxFreshnessAge, 30 * 24 * time.Hour} {
		for _, age := range []time.Duration{maxAge - time.Nanosecond, maxAge, maxAge + time.Nanosecond, 8 * 24 * time.Hour} {
			_, err = validateFreshnessTime([]verify.TimestampVerificationResult{{Type: "Tlog", Timestamp: now.Add(-age)}}, now, maxAge)
			if age > maxAge {
				require.ErrorContains(t, err, "stale")
			} else {
				require.NoError(t, err)
			}
		}
		_, err = validateFreshnessTime(timestamps, now, maxAge)
		require.NoError(t, err)
		_, err = validateFreshnessTime([]verify.TimestampVerificationResult{{Type: "Tlog", Timestamp: now.Add(MaxFreshnessFutureSkew + time.Nanosecond)}}, now, maxAge)
		require.ErrorContains(t, err, "in the future")
	}
}

func TestAuthenticateFreshnessRejectsInvalidMaxAge(t *testing.T) {
	for _, maxAge := range []time.Duration{-time.Nanosecond, -time.Hour} {
		_, err := AuthenticateFreshnessWithMaxAge(nil, nil, time.Now(), maxAge)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
	}
}
