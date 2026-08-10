package provenance

import (
	_ "embed"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/platform-freshness-public.json
var publicFreshnessBundle []byte

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
}

func TestValidateFreshnessTime(t *testing.T) {
	now := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	timestamps := []verify.TimestampVerificationResult{
		{Type: "TimestampAuthority", Timestamp: now.Add(-time.Hour)},
		{Type: "Tlog", Timestamp: now.Add(-2 * time.Hour)},
		{Type: "Tlog", Timestamp: now.Add(-3 * time.Hour)},
	}
	loggedAt, err := validateFreshnessTime(timestamps, now)
	require.NoError(t, err)
	assert.Equal(t, now.Add(-3*time.Hour), loggedAt)

	_, err = validateFreshnessTime(nil, now)
	assert.ErrorContains(t, err, "no verified transparency-log timestamp")

	_, err = validateFreshnessTime([]verify.TimestampVerificationResult{{Type: "TimestampAuthority", Timestamp: now.Add(-time.Hour)}}, now)
	assert.ErrorContains(t, err, "no verified transparency-log timestamp")

	_, err = validateFreshnessTime([]verify.TimestampVerificationResult{{Type: "Tlog", Timestamp: now.Add(MaxFreshnessFutureSkew + time.Second)}}, now)
	assert.ErrorContains(t, err, "in the future")

	_, err = validateFreshnessTime([]verify.TimestampVerificationResult{{Type: "Tlog", Timestamp: now.Add(-MaxFreshnessAge - time.Second)}}, now)
	assert.ErrorContains(t, err, "stale")
}

func TestAuthenticatePublicFreshnessBundle(t *testing.T) {
	expected := &AuthenticatedArtifact{
		Repo:        platformEndorsementsRepo,
		Tag:         "v0.0.4",
		Commit:      "d12ef1e789a782688a681f695e779a64fe1aef3d",
		SubjectName: "platform-endorsements.json",
		Digest:      "2018b30dca0141ed6c470bac99a7ad8026568e1c39d19e560c6b9025a038916c",
	}
	now := time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC)

	loggedAt, err := AuthenticateFreshness(publicFreshnessBundle, expected, now)
	require.NoError(t, err)
	assert.True(t, loggedAt.Equal(time.Date(2026, 8, 9, 19, 15, 18, 0, time.UTC)))
}
