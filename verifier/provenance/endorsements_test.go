package provenance

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLatestPlatformEndorsements is a live test against the published
// artifact (GitHub proxy + Sigstore TUF/Rekor). Run with -short to exclude
// it offline. It also skips until the publisher's first release carrying the
// tinfoil.hash + attestation is reachable through the proxy.
func TestLatestPlatformEndorsements(t *testing.T) {
	if testing.Short() {
		t.Skip("live external services test; skipped with -short")
	}
	digest, err := fetchLatestDigest(platformEndorsementsRepo)
	if err != nil {
		// The proxy surfaces missing release assets as 4xx; skip until the
		// first release carrying the endorsement assets is tagged.
		t.Skipf("platform-endorsements digest not fetchable (asset not published yet?): %v", err)
	}

	client := testClient(t)

	bundleJSON, err := fetchAttestationBundle(platformEndorsementsRepo, digest)
	require.NoError(t, err)

	artifact, err := client.AuthenticateEndorsements(bundleJSON, digest)
	if err != nil && strings.Contains(err.Error(), "accepted_mr_seams") {
		t.Skipf("published artifact predates the mr_seam policy schema; release the updated artifact: %v", err)
	}
	require.NoError(t, err)

	assert.NotEmpty(t, artifact.Machines)
	assert.NotEmpty(t, artifact.Policies)
	for identifier, policyName := range artifact.Machines {
		_, _, err := artifact.PolicyFor(identifier, artifact.Policies[policyName].Platform)
		assert.NoError(t, err)
	}
}
