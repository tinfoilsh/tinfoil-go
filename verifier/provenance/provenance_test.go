package provenance

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

func TestSigningIdentity(t *testing.T) {
	pattern, err := signingIdentity("tinfoilsh/confidential-model")
	require.NoError(t, err)
	re := regexp.MustCompile(pattern)

	assert.True(t, re.MatchString(
		"https://github.com/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/tags/v1.2.3"))

	for name, san := range map[string]string{
		"other repo prefix":     "https://github.com/tinfoilsh/confidential-modelx/.github/workflows/release.yml@refs/tags/v1",
		"unescaped dot in host": "https://githubXcom/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/tags/v1",
		"branch ref":            "https://github.com/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/heads/main",
		"nested workflow path":  "https://github.com/tinfoilsh/confidential-model/.github/workflows/a/b.yml@refs/tags/v1",
		"trailing content":      "https://github.com/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/tags/v1@evil",
		"embedded match":        "prefix https://github.com/tinfoilsh/confidential-model/.github/workflows/release.yml@refs/tags/v1",
	} {
		assert.False(t, re.MatchString(san), name)
	}

	for _, repo := range []string{"", "noslash", "a/b/c", "a/(b|c)"} {
		_, err := signingIdentity(repo)
		assert.Error(t, err, repo)
	}
}

func TestAuthenticateCode(t *testing.T) {
	if testing.Short() {
		t.Skip("live external services test; skipped with -short")
	}
	client := testClient(t)

	const repo = "tinfoilsh/confidential-debug"
	const hexDigest = "910ee7535b0d3e4918e59972994977c2ab6c3e093081885c357a9088d6492402"
	bundle, err := fetchAttestationBundle(repo, hexDigest)
	require.NoError(t, err)

	code, err := client.AuthenticateCode(bundle, repo, hexDigest)
	require.NoError(t, err)
	m := code.Measurement
	assert.Equal(t, measurement.SnpTdxMultiPlatformV1, m.Type)
	assert.Equal(t, []string{
		"e64db4b8914b7317017cd6761f4b60c41d80865ae6e3153a4827ac2a77fe4214bcf724b4525b4b906cfc871e51a5ba7f", // SEV-SNP
		"46658ae5655794d3ea0130e2d425aa002f224c7a47c1eb1792f656d79f808aac6006ce84d71ee24d97c3eea42c867e51", // RTMR1
		"3aa09dae28537d875c10b95b4c07317a6ca442cdb5385a8779ed26b3c67be303055c9efdadef2494a9249932e91cb8e7", // RTMR2
	}, m.Registers)
	require.NotNil(t, code.Shape)
	assert.Equal(t, 4, code.Shape.CPUs)
	assert.Equal(t, 4096, code.Shape.MemoryMB)
	assert.Equal(t, 3, code.Shape.Disks)
	require.NotNil(t, code.Shape.GPUs)
	assert.Equal(t, 0, *code.Shape.GPUs)
}

// testClient builds a client from the SDK's embedded trusted root, exactly
// as production verification does.
func testClient(t *testing.T) *Client {
	t.Helper()
	client, err := getDefaultClient()
	require.NoError(t, err)
	return client
}
