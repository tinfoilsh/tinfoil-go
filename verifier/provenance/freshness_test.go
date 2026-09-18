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

	_, err = validateFreshnessTime([]verify.TimestampVerificationResult{{Type: "Tlog", Timestamp: now.Add(MaxFreshnessFutureSkew + time.Second)}}, now, MaxFreshnessAge)
	assert.ErrorContains(t, err, "in the future")

	_, err = validateFreshnessTime([]verify.TimestampVerificationResult{{Type: "Tlog", Timestamp: now.Add(-MaxFreshnessAge - time.Second)}}, now, MaxFreshnessAge)
	assert.ErrorContains(t, err, "stale")
}

func TestFreshnessMaxAgeBoundary(t *testing.T) {
	loggedAt := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	timestamps := []verify.TimestampVerificationResult{{Type: "Tlog", Timestamp: loggedAt}}
	for _, age := range []time.Duration{time.Hour, MaxFreshnessAge, 14 * 24 * time.Hour} {
		deadline := loggedAt.Add(age)
		_, err := validateFreshnessTime(timestamps, deadline.Add(-time.Nanosecond), age)
		require.NoError(t, err)
		_, err = validateFreshnessTime(timestamps, deadline, age)
		require.ErrorContains(t, err, "stale")
		_, err = validateFreshnessTime(timestamps, deadline.Add(time.Nanosecond), age)
		require.ErrorContains(t, err, "stale")
	}
	// A custom age changes acceptance as well as the returned expiration.
	_, err := validateFreshnessTime(timestamps, loggedAt.Add(8*24*time.Hour), MaxFreshnessAge)
	require.ErrorContains(t, err, "stale")
	_, err = validateFreshnessTime(timestamps, loggedAt.Add(8*24*time.Hour), 14*24*time.Hour)
	require.NoError(t, err)
	_, err = validateFreshnessTime(timestamps, loggedAt.Add(2*time.Hour), time.Hour)
	require.ErrorContains(t, err, "stale")
}

func TestAuthenticateFreshnessRejectsNonPositiveAge(t *testing.T) {
	for _, age := range []time.Duration{0, -time.Second} {
		_, err := (&Client{}).AuthenticateFreshnessWithMaxAge(nil, nil, time.Now(), age)
		require.ErrorContains(t, err, "must be positive")
	}
}
