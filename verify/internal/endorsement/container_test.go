package endorsement

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

// The recorded bundle is the published build attestation of the image with
// this digest. Its certificate names the workflow identity
// https://github.com/tinfoilsh/measure-image-action/.github/workflows/build.yml@refs/tags/build-v0.14.2.
const (
	recordedContainerBundle = "testdata/container-provenance-bundle.json"
	recordedContainerDigest = "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1"
)

func TestAuthenticateContainer(t *testing.T) {
	bundle, err := os.ReadFile(recordedContainerBundle)
	require.NoError(t, err)
	client := testClient(t)
	recorded := configendorsement.ContainerProvenance{
		Digest: recordedContainerDigest, Repository: "tinfoilsh/measure-image-action", RepositoryID: "924941172",
		Workflow: "build.yml", Ref: "refs/tags/build-v*",
	}
	require.NoError(t, client.authenticateContainer(bundle, recorded))

	for name, tt := range map[string]struct {
		change    func(*configendorsement.ContainerProvenance)
		wantError string
	}{
		"another image":         {func(r *configendorsement.ContainerProvenance) { r.Digest = "00" + r.Digest[2:] }, "verifying container provenance"},
		"another repository":    {func(r *configendorsement.ContainerProvenance) { r.Repository = "tinfoilsh/measure-image" }, "source repository \""},
		"another repository ID": {func(r *configendorsement.ContainerProvenance) { r.RepositoryID = "92494117" }, "source repository ID"},
		"another workflow":      {func(r *configendorsement.ContainerProvenance) { r.Workflow = "release.yml" }, "workflow identity"},
		"another ref":           {func(r *configendorsement.ContainerProvenance) { r.Ref = "refs/tags/v*" }, "source ref"},
	} {
		t.Run(name, func(t *testing.T) {
			required := recorded
			tt.change(&required)
			require.ErrorContains(t, client.authenticateContainer(bundle, required), tt.wantError)
		})
	}
}

func TestRefMatches(t *testing.T) {
	for _, tt := range []struct {
		name, pattern, ref string
		want               bool
	}{
		{"literal", "refs/heads/main", "refs/heads/main", true},
		{"literal prefix", "refs/heads/main", "refs/heads/maintenance", false},
		{"literal is not a pattern", "refs/tags/v1.2", "refs/tags/v1x2", false},
		{"fewer segments", "refs/tags/*", "refs/tags", false},
		{"more segments", "refs/tags/*", "refs/tags/v1/extra", false},
		{"alone", "refs/tags/*", "refs/tags/v1.2.3", true},
		{"alone, empty match", "refs/tags/*", "refs/tags/", true},
		{"at the end", "refs/tags/build-v*", "refs/tags/build-v0.14.2", true},
		{"at the end, empty match", "refs/tags/build-v*", "refs/tags/build-v", true},
		{"at the end, another start", "refs/tags/build-v*", "refs/tags/rebuild-v1", false},
		{"at the end, across a separator", "refs/tags/build-v*", "refs/tags/build-v1/2", false},
		{"at the start", "refs/tags/*-rc", "refs/tags/v1-rc", true},
		{"at the start, another end", "refs/tags/*-rc", "refs/tags/v1-rc1", false},
		{"in the middle", "refs/tags/v*-rc", "refs/tags/v1.2-rc", true},
		{"in the middle, empty match", "refs/tags/v*-rc", "refs/tags/v-rc", true},
		{"in the middle, ends overlap", "refs/tags/ab*ba", "refs/tags/aba", false},
		{"several", "refs/tags/v*.*.*", "refs/tags/v1.2.3", true},
		{"several, piece missing", "refs/tags/v*.*.*", "refs/tags/v1.2", false},
		{"several, earliest occurrence", "refs/tags/*ab*ab*", "refs/tags/abab", true},
		{"several, out of order", "refs/tags/*a*b*", "refs/tags/ba", false},
		{"several, adjacent", "refs/tags/v**", "refs/tags/v1", true},
		{"in several segments", "refs/*/v*", "refs/tags/v1", true},
		{"in several segments, across a separator", "refs/*/v*", "refs/remotes/origin/v1", false},
		{"many, near miss", "refs/tags/" + strings.Repeat("*a", 2000) + "*b*", "refs/tags/" + strings.Repeat("a", 4000), false},
		{"many, match", "refs/tags/" + strings.Repeat("*a", 2000) + "*b*", "refs/tags/" + strings.Repeat("a", 4000) + "b", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, refMatches(tt.pattern, tt.ref))
		})
	}
}
