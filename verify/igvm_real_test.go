package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sevabi "github.com/tinfoilsh/go-sev-guest/abi"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/provenance"
)

// The fixtures under testdata/igvm are genuine, not synthetic:
//
//	platform-endorsements-igvm.json  release v0.0.16 of platform-endorsements
//	platform-bundle.json             its real attestation, from the GitHub API
//	sev-snp-report.bin               a real SEV-SNP report from an AMD Turin
//	                                 host that booted cvmimage v0.15.0-rc6
//	config-b.yaml                    the exact config disk that boot used
//	tinfoil-inference-…-manifest.json  the manifest cvmimage publishes today
//
// The platform bundle is authenticated against the production Sigstore root
// this module embeds, so these tests fail if the real publishing identity,
// subject or digest changes.
//
// The runtime measurement is the one part that cannot be real yet: cvmimage
// publishes it in the manifest file above, and this verifier reads it from an
// attestation predicate cvmimage does not emit yet. The predicate is built
// from the manifest's own values in the provenance package's tests.
//
// config-b.yaml must be replaced before this branch is published: it is the
// literal config a developer booted and carries an operator SSH public key.
// Its exact bytes are what make the HOST_DATA assertion real, so replacing it
// means re-capturing a report on hardware under a config written for the
// purpose. config-placeholder.yaml is derived and its copy is already a
// placeholder.
const (
	realPlatformSHA = "c4f46b52976c8d2660f7067fc491eb87c58573671d325b79ef0ca5e97493c40a"
	realPlatformTag = "v0.0.16"
	realHostData    = "301396c526d83a0ea03f823dd3a8621d9defc90e74d05e63f03325ae0fbc4ff0"
	realTurinPolicy = "amd-turin-prod"
	realGenoaPolicy = "amd-genoa-prod"
	realTDXPolicy   = "tdx-h200-prod"
)

func igvmFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "igvm", name))
	require.NoError(t, err)
	return data
}

// TestRealPlatformEndorsements authenticates the IGVM platform artifact under
// the real Sigstore root and shows it parses: every policy declares a config
// binding, and no policy or measurement names a VM shape, because a
// shape-independent image needs none.
func TestRealPlatformEndorsements(t *testing.T) {
	artifact := realPlatformArtifact(t)
	assert.Empty(t, artifact.Measurements, "the IGVM artifact needs no shape-specific measurements")
	require.NotEmpty(t, artifact.Policies)
	for name, p := range artifact.Policies {
		switch p.Platform {
		case policy.PlatformSEVSNP:
			assert.Equal(t, policy.ConfigBindingSHA256, p.SEVSNP.ConfigBinding, name)
			assert.Empty(t, p.SEVSNP.HostData, name)
		case policy.PlatformTDX:
			assert.Equal(t, policy.ConfigBindingSHA256, p.TDX.ConfigBinding, name)
			assert.Empty(t, p.TDX.PlatformMeasurements, name)
		}
	}
}

func realPlatformArtifact(t *testing.T) *policy.Artifact {
	t.Helper()
	client, err := provenance.NewDefaultClient()
	require.NoError(t, err)
	endorsements, err := client.AuthenticatePlatformEndorsements(
		igvmFixture(t, "platform-bundle.json"),
		"tinfoilsh/platform-endorsements", realPlatformTag, realPlatformSHA)
	require.NoError(t, err)
	require.Equal(t, "platform-endorsements-igvm.json", endorsements.SubjectName)
	return endorsements.Artifact
}

// TestRealArtifactIsUnusableUnresolved is the fail-closed property the design
// rests on: the published artifact names no HOST_DATA and no platform
// measurements, so a verifier that never learned a config cannot appraise
// anything with it.
func TestRealArtifactIsUnusableUnresolved(t *testing.T) {
	artifact := realPlatformArtifact(t)
	snp := artifact.Policies[realTurinPolicy].SEVSNP
	require.NotNil(t, snp)
	require.NoError(t, snp.Validate(), "the policy is well-formed, just incomplete")
	assert.Empty(t, snp.HostData, "nothing to compare HOST_DATA against")

	tdx := artifact.Policies[realTDXPolicy].TDX
	require.NotNil(t, tdx)
	require.NoError(t, tdx.Validate())
	assert.Empty(t, tdx.MRConfigID)
	assert.Empty(t, tdx.PlatformMeasurements)
}

// TestRealLaunchResolution is the join: the real published policy, resolved
// against the digest of the real config disk, produces exactly the register
// the real hardware reported.
func TestRealLaunchResolution(t *testing.T) {
	// The real boot's config disk: its digest is what the guest put in
	// HOST_DATA, which is how we know the hashing convention is the one the
	// guest implements and not one this test invented.
	configDigest := sha256.Sum256(igvmFixture(t, "config-b.yaml"))
	require.Equal(t, realHostData, hex.EncodeToString(configDigest[:]),
		"the real report's HOST_DATA is sha256 of the real config disk")

	resolved, err := realPlatformArtifact(t).Resolve(hex.EncodeToString(configDigest[:]))
	require.NoError(t, err)

	for _, name := range []string{realTurinPolicy, realGenoaPolicy} {
		snp := resolved.Policies[name].SEVSNP
		require.NotNil(t, snp, name)
		assert.Equal(t, realHostData, snp.HostData, name)
		assert.Empty(t, snp.ConfigBinding, name)
	}

	// TDX: the same digest in a 48-byte register, padded with the 16 zero
	// bytes the launch writes after it.
	tdx := resolved.Policies[realTDXPolicy].TDX
	require.NotNil(t, tdx)
	assert.Equal(t, realHostData+strings.Repeat("0", 32), tdx.MRConfigID)
	assert.Empty(t, tdx.ConfigBinding)

	// And the register the resolution produced is the report's own.
	report, err := sevabi.ReportToProto(igvmFixture(t, "sev-snp-report.bin"))
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(report.GetHostData()), resolved.Policies[realTurinPolicy].SEVSNP.HostData)
}
