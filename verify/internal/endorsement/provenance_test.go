package endorsement

import (
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/testing/data"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/endorsement/freshness"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/policy"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
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

func TestPinnedWorkflowIdentitiesAreAnchored(t *testing.T) {
	assert.Equal(t,
		`^https://github\.com/tinfoilsh/cvmimage/\.github/workflows/platform-release\.yml@refs/tags/platform-v[0-9][^@]*$`,
		platformEndorsementsIdentity,
	)
	assert.Equal(t,
		`^https://github\.com/tinfoilsh/freshness-witness/\.github/workflows/freshness\.yml@refs/heads/main$`,
		freshnessWitnessIdentity,
	)
}

func TestLiveAuthenticateCode(t *testing.T) {
	testutil.RequireLive(t)
	client := testClient(t)

	const repo = "tinfoilsh/confidential-debug"
	const tag = "v0.0.52"
	const hexDigest = "910ee7535b0d3e4918e59972994977c2ab6c3e093081885c357a9088d6492402"
	bundle, err := fetchAttestationBundle(repo, hexDigest)
	require.NoError(t, err)

	code, err := client.AuthenticateCode(bundle, repo, tag, hexDigest)
	require.NoError(t, err)
	assert.Equal(t, repo, code.Repo)
	assert.Equal(t, tag, code.Tag)
	assert.Equal(t, "tinfoil-deployment.json", code.SubjectName)
	assert.Equal(t, hexDigest, code.Digest)
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

	for _, tt := range []struct {
		ref, tagHint, digestHint string
		valid                    bool
	}{
		{repo, tag, hexDigest, true},
		{repo + "@" + tag, "untrusted-tag", hexDigest, true},
		{repo + "@sha256:" + hexDigest, tag, "untrusted-digest", true},
		{repo + "@" + tag + "@sha256:" + hexDigest, "untrusted-tag", "untrusted-digest", true},
		{repo + "@wrong-tag", tag, hexDigest, false},
		{repo + "@sha256:" + strings.Repeat("00", 32), tag, hexDigest, false},
		{repo + "@wrong-tag@sha256:" + hexDigest, tag, hexDigest, false},
	} {
		t.Run(tt.ref, func(t *testing.T) {
			got, err := client.AuthenticateCode(bundle, tt.ref, tt.tagHint, tt.digestHint)
			if tt.valid {
				require.NoError(t, err)
				require.Equal(t, code, got)
			} else {
				require.Error(t, err)
				require.Nil(t, got)
			}
		})
	}
}

func TestAuthenticateCodeRejectsInvalidReference(t *testing.T) {
	client := testClient(t)
	for _, ref := range []string{"", "org/repo@", "org/repo@sha256:bad", "org/repo@v1@v2", "org/repo/extra", "org/(repo|other)"} {
		_, err := client.AuthenticateCode(nil, ref, "", "")
		require.ErrorContains(t, err, "invalid release reference")
	}
}

func TestAuthenticatedArtifactPinsRepositoryIdentity(t *testing.T) {
	const otherOrganizationID = "1"
	for _, repository := range []struct {
		name, id, otherID string
	}{
		{collateral.RuntimeRepo, runtimeRepoID, "1"},
	} {
		t.Run(repository.name, func(t *testing.T) {
			for _, tt := range []struct {
				name, repositoryID, ownerID, wantError string
			}{
				{"matching IDs", repository.id, tinfoilOrganizationID, ""},
				{"different repository", repository.otherID, tinfoilOrganizationID, "source repository ID"},
				{"missing repository", "", tinfoilOrganizationID, "source repository ID"},
				{"different organization", repository.id, otherOrganizationID, "source repository owner ID"},
				{"missing organization", repository.id, "", "source repository owner ID"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					expected := testAuthenticatedArtifact()
					expected.Repo = repository.name
					result := &verify.VerificationResult{
						Signature: &verify.SignatureVerificationResult{Certificate: &certificate.Summary{Extensions: certificate.Extensions{
							SourceRepositoryIdentifier:      tt.repositoryID,
							SourceRepositoryOwnerIdentifier: tt.ownerID,
							SourceRepositoryRef:             "refs/tags/" + expected.Tag,
							SourceRepositoryDigest:          expected.Commit,
						}}},
						Statement: &in_toto.Statement{Subject: []*in_toto.ResourceDescriptor{{Name: expected.SubjectName}}},
					}
					got, err := authenticatedArtifact(result, expected.Repo, expected.Tag, expected.Digest, "artifact")
					if tt.wantError != "" {
						require.ErrorContains(t, err, tt.wantError)
						require.Equal(t, AuthenticatedArtifact{}, got)
						return
					}
					require.NoError(t, err)
					require.Equal(t, *expected, got)
				})
			}
		})
	}
}

func testClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewDefaultClient()
	require.NoError(t, err)
	return client
}

func TestPlatformPublisher(t *testing.T) {
	identity := regexp.MustCompile(platformEndorsementsIdentity)
	const prefix = "https://github.com/tinfoilsh/cvmimage/.github/workflows/"
	require.True(t, identity.MatchString(prefix+"platform-release.yml@refs/tags/platform-v1.2.3"))
	for _, san := range []string{
		prefix + "release.yml@refs/tags/platform-v1.2.3",
		prefix + "platform-release.yml@refs/tags/v1.2.3",
		prefix + "platform-release.yml@refs/heads/platform-v1.2.3",
		prefix + "platform-release.yml@refs/tags/platform-v1.2.3@extra",
		"https://github.com/tinfoilsh/platform-endorsements/.github/workflows/build.yml@refs/tags/v1.2.3",
	} {
		require.False(t, identity.MatchString(san), san)
	}

	client := testClient(t)
	for _, tt := range []struct{ repo, format string }{
		{"tinfoilsh/platform-endorsements", policy.ArtifactFormatV2},
		{"tinfoilsh/platform-endorsements", policy.ArtifactFormat},
		{freshness.PlatformRepo, "unsupported"},
	} {
		_, err := client.AuthenticatePlatformEndorsements(nil, tt.repo, "platform-v1.2.3", strings.Repeat("a", 64), tt.format)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "parsing bundle")
	}
}

func TestPlatformRejectsOtherSigningIdentity(t *testing.T) {
	client := testClient(t)
	client.trustRoot = data.TrustedRoot(t, "scaffolding.json")
	b := data.Bundle(t, "othername.sigstore.json")
	bundleJSON, err := b.MarshalJSON()
	require.NoError(t, err)
	digest := b.GetMessageSignature().GetMessageDigest().GetDigest()

	verifier, err := verify.NewSignedEntityVerifier(client.trustRoot, client.verifierOptions...)
	require.NoError(t, err)
	identity, err := verify.NewShortCertificateIdentity("http://oidc.local:8080", "", "foo!oidc.local", "")
	require.NoError(t, err)
	_, err = verifier.Verify(b, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(identity)))
	require.NoError(t, err)
	for _, format := range []string{policy.ArtifactFormat, policy.ArtifactFormatV2} {
		t.Run(format, func(t *testing.T) {
			got, err := client.AuthenticatePlatformEndorsements(bundleJSON, freshness.PlatformRepo, "platform-v1.2.3", hex.EncodeToString(digest), format)
			var identityError *verify.ErrNoMatchingCertificateIdentity
			require.ErrorAs(t, err, &identityError)
			require.ErrorContains(t, err, "expected SAN value to match regex")
			require.Nil(t, got)
		})
	}
}
