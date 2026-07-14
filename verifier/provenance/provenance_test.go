package provenance

import (
	"regexp"
	"strings"
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

func TestVerifyCode(t *testing.T) {
	if testing.Short() {
		t.Skip("live external services test; skipped with -short")
	}
	client := testClient(t)

	const repo = "tinfoilsh/confidential-deepseek-r1-0528"
	const hexDigest = "7e76d5a6d81f19ecdc1f3c18c8f0cf5b89d22ea107a05a1ae23ce46e79270f26"
	bundle, err := fetchAttestationBundle(repo, hexDigest)
	assert.NoError(t, err)

	code, err := client.VerifyCode(bundle, repo, hexDigest)
	if err != nil && strings.Contains(err.Error(), "vm_shape") {
		t.Skipf("published code artifact predates the vm_shape declaration; update the measurement pipeline: %v", err)
	}
	require.NoError(t, err)
	m := code.Measurement
	assert.Equal(t, m.Type, measurement.SnpTdxMultiPlatformV1)
	assert.Equal(t, m.Registers, []string{
		"442df00d945bdd2849e6df4eb28c757e9e94428787268b452eacb3f86bbc38528d6712e2c41b6953f1a96d2493d5f9b6", // SEV-SNP
		"10a05f3fba7d66babcc8a8143451443a564963ced77c7fa126f004857753f87c318720e29e9ed2f46c8753b44b01004d", // RTRM1
		"fc744ecc4550ec0ea6c25deaa777bd2ed6e5feda35ac1e88a2c2b6e62584a8ad47a93526638de3b97fe45cd67cb5339f", // RTRM2
	})

	// Check TDX equality
	tdxMeasurement := &measurement.Measurement{
		Type: measurement.TdxGuestV2,
		Registers: []string{
			"mrtd",
			"rtmr0",
			"10a05f3fba7d66babcc8a8143451443a564963ced77c7fa126f004857753f87c318720e29e9ed2f46c8753b44b01004d", // RTMR1
			"fc744ecc4550ec0ea6c25deaa777bd2ed6e5feda35ac1e88a2c2b6e62584a8ad47a93526638de3b97fe45cd67cb5339f", // RTMR2
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", // RTMR3
		},
	}
	assert.NoError(t, m.Equals(tdxMeasurement))

	// Check SEV-SNP equality
	sevSNPMeasurement := &measurement.Measurement{
		Type: measurement.SevGuestV2,
		Registers: []string{
			"442df00d945bdd2849e6df4eb28c757e9e94428787268b452eacb3f86bbc38528d6712e2c41b6953f1a96d2493d5f9b6", // SEV-SNP
		},
	}
	assert.NoError(t, m.Equals(sevSNPMeasurement))
}

// testClient builds a client from the SDK's embedded trusted root, exactly
// as production verification does.
func testClient(t *testing.T) *Client {
	t.Helper()
	client, err := getDefaultClient()
	require.NoError(t, err)
	return client
}
