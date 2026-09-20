package provenance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLatestPlatformEndorsements is a live test against the published
// artifact (GitHub proxy + Sigstore TUF/Rekor). Run with -short to exclude
// it offline.
func TestLatestPlatformEndorsements(t *testing.T) {
	if testing.Short() {
		t.Skip("live external services test; skipped with -short")
	}
	digest, err := fetchLatestDigest(platformEndorsementsRepo)
	require.NoError(t, err)

	client := testClient(t)

	bundleJSON, err := fetchAttestationBundle(platformEndorsementsRepo, digest)
	require.NoError(t, err)

	artifact, err := client.AuthenticateEndorsements(bundleJSON, digest)
	require.NoError(t, err)

	assert.NotEmpty(t, artifact.Machines)
	assert.NotEmpty(t, artifact.Policies)
	for identifier, policyName := range artifact.Machines {
		_, _, err := artifact.PolicyFor(identifier, artifact.Policies[policyName].Platform)
		assert.NoError(t, err)
	}
}
