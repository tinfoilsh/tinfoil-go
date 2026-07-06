package sigstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/github"
)

// TestLatestPlatformEndorsements is a live test against the published
// artifact. It skips until the publisher's first release carrying the
// tinfoil.hash + attestation is reachable through the proxy.
func TestLatestPlatformEndorsements(t *testing.T) {
	if _, err := github.FetchLatestDigest(platformEndorsementsRepo); err != nil {
		// The proxy surfaces missing release assets as 4xx; skip until the
		// first release carrying the endorsement assets is tagged.
		t.Skipf("platform-endorsements digest not fetchable (asset not published yet?): %v", err)
	}

	client, err := NewClient()
	require.NoError(t, err)

	artifact, err := client.LatestPlatformEndorsements()
	require.NoError(t, err)

	assert.NotEmpty(t, artifact.Machines)
	assert.NotEmpty(t, artifact.Policies)
	for identifier, policyName := range artifact.Machines {
		_, _, err := artifact.PolicyFor(identifier, artifact.Policies[policyName].Platform)
		assert.NoError(t, err)
	}
}
