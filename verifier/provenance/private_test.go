package provenance

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	privateFixtureRepo   = "tinfoilsh/private-attestation-e2e"
	privateFixtureTag    = "v1.0.1"
	privateFixtureCommit = "69a541884f63ab38ec725f0d7e02e06595b875f0"
	privateFixtureDigest = "5ea52b374e0ce8da0367c17a7d954392c07dcf26993bc2bc57fa540b9b858baa"
)

func readPrivateFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return b
}

func TestPrivateGitHubSource(t *testing.T) {
	code, err := AuthenticateCode(readPrivateFixture(t, "private-source.json"), privateFixtureRepo, privateFixtureTag, privateFixtureDigest)
	require.NoError(t, err)
	require.Equal(t, privateFixtureRepo, code.Repo)
	require.Equal(t, privateFixtureTag, code.Tag)
	require.Equal(t, privateFixtureCommit, code.Commit)
	require.Equal(t, privateFixtureDigest, code.Digest)
	require.Equal(t, "tinfoil-deployment.json", code.SubjectName)
	require.Equal(t, []string{strings.Repeat("1", 96), strings.Repeat("2", 96), strings.Repeat("3", 96)}, code.Measurement.Registers)
	require.Equal(t, 2, code.Shape.CPUs)
	require.Equal(t, 4096, code.Shape.MemoryMB)
}

func TestPrivateGitHubSourceRejectsUntrustedEvidence(t *testing.T) {
	for _, name := range []string{"wrong repository", "wrong tag", "wrong digest", "wrong root", "missing timestamp", "altered timestamp", "altered payload", "public log with private timestamp"} {
		t.Run(name, func(t *testing.T) {
			var b map[string]any
			require.NoError(t, json.Unmarshal(readPrivateFixture(t, "private-source.json"), &b))
			material := b["verificationMaterial"].(map[string]any)
			repo, tag, digest := privateFixtureRepo, privateFixtureTag, privateFixtureDigest
			privateRoot := embeddedGitHubTrustedRoot
			switch name {
			case "wrong repository":
				repo = "another/repository"
			case "wrong tag":
				tag = "v1.0.2"
			case "wrong digest":
				digest = strings.Repeat("0", 64)
			case "wrong root":
				privateRoot = embeddedTrustedRoot
			case "missing timestamp":
				delete(material, "timestampVerificationData")
			case "altered timestamp":
				timestamps := material["timestampVerificationData"].(map[string]any)["rfc3161Timestamps"].([]any)
				timestamp := timestamps[0].(map[string]any)
				der, err := base64.StdEncoding.DecodeString(timestamp["signedTimestamp"].(string))
				require.NoError(t, err)
				der[len(der)-1] ^= 1
				timestamp["signedTimestamp"] = base64.StdEncoding.EncodeToString(der)
			case "altered payload":
				envelope := b["dsseEnvelope"].(map[string]any)
				payload, err := base64.StdEncoding.DecodeString(envelope["payload"].(string))
				require.NoError(t, err)
				envelope["payload"] = base64.StdEncoding.EncodeToString(append(payload, ' '))
			case "public log with private timestamp":
				var entry map[string]any
				require.NoError(t, json.Unmarshal(readPrivateFixture(t, "public-log-entry.json"), &entry))
				material["tlogEntries"] = []any{entry}
			}
			client, err := NewClientFromTrustedRoots(embeddedTrustedRoot, privateRoot)
			require.NoError(t, err)
			bundle, err := json.Marshal(b)
			require.NoError(t, err)
			code, err := client.AuthenticateCode(bundle, repo, tag, digest)
			require.Error(t, err)
			require.Nil(t, code)
		})
	}
}

func TestPrivateGitHubFreshnessFixture(t *testing.T) {
	client := testClient(t)
	bundle := readPrivateFixture(t, "private-freshness.json")
	identity := "^" + regexp.QuoteMeta("https://github.com/tinfoilsh/freshness-witness/.github/workflows/private.yml@refs/heads/codex/private-repo-v3-e2e") + "$"
	result, payload, err := client.verifyBundleWithIdentity(bundle, identity, privateFixtureDigest)
	require.NoError(t, err)
	expected := &AuthenticatedArtifact{Repo: privateFixtureRepo, Tag: privateFixtureTag, Commit: privateFixtureCommit, SubjectName: "tinfoil-deployment.json", Digest: privateFixtureDigest}
	statement, err := parseFreshnessStatement(payload)
	require.NoError(t, err)
	require.NoError(t, validateWitness(statement.Predicate, expected))
	now := time.Date(2026, 8, 28, 10, 12, 0, 0, time.UTC)
	endorsedAt, err := validateFreshnessTime(result.VerifiedTimestamps, now, MaxFreshnessAge)
	require.NoError(t, err)
	require.WithinDuration(t, now, endorsedAt, time.Minute)
	_, err = validateFreshnessTime(result.VerifiedTimestamps, now.Add(MaxFreshnessAge), MaxFreshnessAge)
	require.ErrorContains(t, err, "stale")
	_, err = validateFreshnessTime(result.VerifiedTimestamps, now.Add(-time.Hour), MaxFreshnessAge)
	require.ErrorContains(t, err, "future")
	// This captured workflow used a test ref; production must require main.
	_, err = client.AuthenticateFreshness(bundle, expected, now, MaxFreshnessAge)
	require.Error(t, err)
}
