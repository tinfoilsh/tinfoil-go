package sigstore

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/github"
)

func TestReleaseIdentityMatchesExactTag(t *testing.T) {
	identity := regexp.MustCompile(releaseIdentity("owner/repo.name", "v1.2.3+build"))

	assert.True(t, identity.MatchString("https://github.com/owner/repo.name/.github/workflows/build.yml@refs/tags/v1.2.3+build"))
	assert.False(t, identity.MatchString("https://github.com/owner/repo.name/.github/workflows/build.yml@refs/tags/v1.2.4"))
	assert.False(t, identity.MatchString("https://github.com/owner/repoXname/.github/workflows/build.yml@refs/tags/v1.2.3+build"))
	assert.False(t, identity.MatchString("https://github.com/owner/repo.name/.github/workflows/build.yml@refs/tags/v1.2.3+build/extra"))
}

func TestFetchHardwarePlatformMeasurements(t *testing.T) {
	if testing.Short() {
		t.Skip("live external services test; skipped with -short")
	}
	client, err := NewClient()
	assert.NoError(t, err)

	const digest = "fe03832f4045909235b2c4f62a2dcfce4212383e48d111f65eb3971af264a9bc"

	measurements, err := client.FetchHardwareMeasurements("tinfoilsh/hardware-measurements", digest)
	assert.NoError(t, err)

	var hw1measurement *attestation.HardwareMeasurement
	for _, measurement := range measurements {
		if measurement.ID == "hw1@"+digest {
			hw1measurement = measurement
			break
		}
	}

	assert.NotNil(t, hw1measurement)
	assert.Equal(t, "7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114", hw1measurement.MRTD)
	assert.Equal(t, hw1measurement.RTMR0, "5c70e5e513f82d930e4740228a51a96fb981dd8e63a583aae5d71c84caaa06c1241c4eaf46faab066d0120e44bf5a1e1")
}

func TestVerifyAttestation(t *testing.T) {
	if testing.Short() {
		t.Skip("live external services test; skipped with -short")
	}
	client, err := NewClient()
	require.NoError(t, err)

	// confidential-model-router v0.0.159
	const repo = "tinfoilsh/confidential-model-router"
	const hexDigest = "1ffc1cde7acd5134367cb9f430024203ed4455a51ee4473f7b3e75bd556d0a6b"
	bundle, err := github.FetchAttestationBundle(repo, hexDigest)
	require.NoError(t, err)

	measurement, err := client.VerifyAttestation(bundle, repo, hexDigest)
	require.NoError(t, err)
	assert.Equal(t, measurement.Type, attestation.SnpTdxMultiPlatformV1)
	assert.Equal(t, measurement.Registers, []string{
		"dd2bc29f91f1bd68b5c946257ab6c89cf801d234ad99bc714ba5521337860b52fc47a48816f5c66ab6775c8b7a7fd0bb", // SEV-SNP
		"7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e", // RTRM1
		"d8514ec73464b650ed3e27bc03b840c176f22790c759515422b91d89e8f36e1ffe2e41dccc4e699ae12cbbab6b1ff8f6", // RTRM2
	})

	// Check TDX equality
	tdxMeasurement := &attestation.Measurement{
		Type: attestation.TdxGuestV2,
		Registers: []string{
			"mrtd",
			"rtmr0",
			"7e57f9877b4533e7dcb8dd7419dfaf422f3c7cef6fd337a4eaf27ae90a751ff04945ef0d4fb6c3753285cb1f09ce048e", // RTMR1
			"d8514ec73464b650ed3e27bc03b840c176f22790c759515422b91d89e8f36e1ffe2e41dccc4e699ae12cbbab6b1ff8f6", // RTMR2
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", // RTMR3
		},
	}
	assert.NoError(t, measurement.Equals(tdxMeasurement))

	// Check SEV-SNP equality
	sevSNPMeasurement := &attestation.Measurement{
		Type: attestation.SevGuestV2,
		Registers: []string{
			"dd2bc29f91f1bd68b5c946257ab6c89cf801d234ad99bc714ba5521337860b52fc47a48816f5c66ab6775c8b7a7fd0bb", // SEV-SNP
		},
	}
	assert.NoError(t, measurement.Equals(sevSNPMeasurement))
}
