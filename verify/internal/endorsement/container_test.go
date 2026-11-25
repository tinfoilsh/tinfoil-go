package endorsement

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	configendorsement "github.com/tinfoilsh/tinfoil-go/endorsement/config"
)

// The recorded bundle is the published build attestation of the image with
// this digest.
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
		Workflow: "build.yml", Ref: "refs/tags/build-v0.14.2", Commit: "01a05df207140a8e8e1d2cd26028ab7c51dad9d1",
	}
	require.NoError(t, client.authenticateContainer(bundle, recorded))

	// The workflow identity ends with the ref, so another ref fails there
	// before it is compared with the source ref.
	for name, tt := range map[string]struct {
		change    func(*configendorsement.ContainerProvenance)
		wantError string
	}{
		"another image":         {func(r *configendorsement.ContainerProvenance) { r.Digest = "00" + r.Digest[2:] }, "verifying container provenance"},
		"another repository":    {func(r *configendorsement.ContainerProvenance) { r.Repository = "tinfoilsh/measure-image" }, "source repository \""},
		"another repository ID": {func(r *configendorsement.ContainerProvenance) { r.RepositoryID = "92494117" }, "source repository ID"},
		"another workflow":      {func(r *configendorsement.ContainerProvenance) { r.Workflow = "release.yml" }, "workflow identity"},
		"ref with a star":       {func(r *configendorsement.ContainerProvenance) { r.Ref = "refs/tags/build-v*" }, "workflow identity"},
		"another commit":        {func(r *configendorsement.ContainerProvenance) { r.Commit = "00" + r.Commit[2:] }, "source commit"},
	} {
		t.Run(name, func(t *testing.T) {
			required := recorded
			tt.change(&required)
			require.ErrorContains(t, client.authenticateContainer(bundle, required), tt.wantError)
		})
	}
}
