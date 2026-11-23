package verify

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// The recorded bundle is the published build attestation of this image.
const (
	recordedContainerDigest = "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1"
	recordedContainerBundle = "internal/endorsement/testdata/container-provenance-bundle.json"
)

func TestConfigRequiringContainerProvenance(t *testing.T) {
	bundle, err := os.ReadFile(recordedContainerBundle)
	require.NoError(t, err)
	const provenance = `    provenance:
      github:
        repository: tinfoilsh/measure-image-action
        repository_id: 924941172
        workflow: build.yml
        ref: refs/tags/build-v*
`
	container := func(name string) string {
		return "  - name: " + name + "\n    image: ghcr.io/tinfoilsh/measure-image-action@sha256:" + recordedContainerDigest + "\n"
	}
	proof := func(id, digest string) collateral.Entry {
		data, err := json.Marshal(map[string]any{"digest": digest, "sigstore_bundle": jsontext.Value(bundle)})
		require.NoError(t, err)
		return collateral.Entry{ID: id, Role: collateral.RoleReferenceValues, Format: collateral.ContainerProvenanceV1Format, Data: data}
	}
	verify := func(t *testing.T, containers string, entries ...collateral.Entry) (*ConfigVerification, error) {
		inputs := embeddedInputs(t)
		config := append(inputs.Config.Bytes, []byte("containers:\n"+containers)...)
		data, err := json.Marshal(map[string][]byte{"config_base64": config})
		require.NoError(t, err)
		entries = append([]collateral.Entry{{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: data}}, entries...)
		_, _, doc := embeddedDocument(t, collateral.FormatV3, entries...)
		inputs.Config = nil
		v, err := newEmbeddedVerifier(inputs)
		require.NoError(t, err)
		v.configAuthorizer = func(collateral.ConfigEndorsement) error { return nil }
		refs, err := v.configReferences(doc, "", time.Now())
		if err != nil {
			return nil, err
		}
		return refs.config, nil
	}

	t.Run("proven", func(t *testing.T) {
		config, err := verify(t, container("first")+provenance+container("second")+provenance+container("unconstrained"), proof("container", recordedContainerDigest))
		require.NoError(t, err)
		want := ContainerVerification{
			Digest: recordedContainerDigest, Repository: "tinfoilsh/measure-image-action", Workflow: "build.yml",
			Ref: "refs/tags/build-v0.14.2", Commit: "01a05df207140a8e8e1d2cd26028ab7c51dad9d1",
		}
		first, second := want, want
		first.Container, second.Container = "first", "second"
		require.Equal(t, []ContainerVerification{first, second}, config.Containers)
	})
	t.Run("no requirement", func(t *testing.T) {
		config, err := verify(t, container("app"))
		require.NoError(t, err)
		require.Empty(t, config.Containers)
	})
	t.Run("proof missing", func(t *testing.T) {
		_, err := verify(t, container("app")+provenance)
		require.ErrorIs(t, err, collateral.ErrNotFound)
		require.ErrorContains(t, err, `container "app" requires provenance`)
	})
	t.Run("proof for another image", func(t *testing.T) {
		_, err := verify(t, container("app")+provenance, proof("container", strings.Repeat("ab", 32)))
		require.ErrorIs(t, err, collateral.ErrNotFound)
	})
	t.Run("proof from another workflow", func(t *testing.T) {
		_, err := verify(t, container("app")+strings.Replace(provenance, "build.yml", "release.yml", 1), proof("container", recordedContainerDigest))
		require.ErrorContains(t, err, `container "app": verifying container provenance`)
	})
	t.Run("requirement the verifier cannot read", func(t *testing.T) {
		_, err := verify(t, container("app")+provenance+"      gitlab: {}\n", proof("container", recordedContainerDigest))
		require.ErrorContains(t, err, `unknown provenance field "gitlab"`)
	})
}
