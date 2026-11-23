package verify

import (
	"bytes"
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

// recordedContainerProvenance is the requirement the recorded bundle meets.
const recordedContainerProvenance = `    provenance:
      github:
        repository: tinfoilsh/measure-image-action
        repository_id: 924941172
        workflow: build.yml
        ref: refs/tags/build-v*
`

// recordedContainer is a config's entry for a container that runs the
// recorded image.
func recordedContainer(name string) string {
	return "  - name: " + name + "\n    image: ghcr.io/tinfoilsh/measure-image-action@sha256:" + recordedContainerDigest + "\n"
}

// recordedContainerProof is a collateral entry that offers the recorded
// bundle as the build attestation of the image with the given digest.
func recordedContainerProof(t *testing.T, digest string) collateral.Entry {
	t.Helper()
	bundle, err := os.ReadFile(recordedContainerBundle)
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{"digest": digest, "sigstore_bundle": jsontext.Value(bundle)})
	require.NoError(t, err)
	return collateral.Entry{ID: "container", Role: collateral.RoleReferenceValues, Format: collateral.ContainerProvenanceV1Format, Data: data}
}

// configEntry is a collateral entry that carries config bytes.
func configEntry(t *testing.T, config []byte) collateral.Entry {
	t.Helper()
	data, err := json.Marshal(map[string][]byte{"config_base64": config})
	require.NoError(t, err)
	return collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: data}
}

func TestConfigRequiringContainerProvenance(t *testing.T) {
	const provenance = recordedContainerProvenance
	container := recordedContainer
	verify := func(t *testing.T, containers string, entries ...collateral.Entry) (*ConfigVerification, error) {
		inputs := embeddedInputs(t)
		config := append(inputs.Config.Bytes, []byte("containers:\n"+containers)...)
		entries = append([]collateral.Entry{configEntry(t, config)}, entries...)
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
		config, err := verify(t, container("first")+provenance+container("second")+provenance+container("unconstrained"), recordedContainerProof(t, recordedContainerDigest))
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
		_, err := verify(t, container("app")+provenance, recordedContainerProof(t, strings.Repeat("ab", 32)))
		require.ErrorIs(t, err, collateral.ErrNotFound)
	})
	t.Run("proof from another workflow", func(t *testing.T) {
		_, err := verify(t, container("app")+strings.Replace(provenance, "build.yml", "release.yml", 1), recordedContainerProof(t, recordedContainerDigest))
		require.ErrorContains(t, err, `container "app": verifying container provenance`)
	})
	t.Run("requirement the verifier cannot read", func(t *testing.T) {
		_, err := verify(t, container("app")+provenance+"      gitlab: {}\n", recordedContainerProof(t, recordedContainerDigest))
		require.ErrorContains(t, err, `provenance has unknown field "gitlab"`)
	})
}

// An embedded config is held to the builds it requires. The requirements of
// one embedded in full come from the caller's bytes, so a document cannot
// leave them out; one embedded by reference is checked when the document
// carries the bytes of that digest.
func TestEmbeddedConfigRequiringContainerProvenance(t *testing.T) {
	requiring := func(t *testing.T) (embeddedTestInputs, []byte) {
		inputs := embeddedInputs(t)
		inputs.Config.Bytes = append(inputs.Config.Bytes, []byte("containers:\n"+recordedContainer("app")+recordedContainerProvenance)...)
		return inputs, inputs.Config.Bytes
	}
	byReference := func(t *testing.T, inputs embeddedTestInputs) embeddedTestInputs {
		reference, err := inputs.Config.reference()
		require.NoError(t, err)
		inputs.Config, inputs.ConfigReference = nil, &reference
		return inputs
	}
	verify := func(t *testing.T, inputs embeddedTestInputs, entries ...collateral.Entry) (*ConfigVerification, error) {
		v, err := newEmbeddedVerifier(inputs)
		require.NoError(t, err)
		_, _, doc := embeddedDocument(t, collateral.FormatV3, entries...)
		refs, err := v.configReferences(doc, "", time.Now())
		if err != nil {
			return nil, err
		}
		return refs.config, nil
	}
	proven := []ContainerVerification{{
		Container: "app", Digest: recordedContainerDigest, Repository: "tinfoilsh/measure-image-action", Workflow: "build.yml",
		Ref: "refs/tags/build-v0.14.2", Commit: "01a05df207140a8e8e1d2cd26028ab7c51dad9d1",
	}}

	t.Run("in full, proven", func(t *testing.T) {
		inputs, _ := requiring(t)
		config, err := verify(t, inputs, recordedContainerProof(t, recordedContainerDigest))
		require.NoError(t, err)
		require.Equal(t, SourceEmbedded, config.Source)
		require.Equal(t, proven, config.Containers)
	})
	t.Run("in full, proof missing", func(t *testing.T) {
		inputs, _ := requiring(t)
		_, err := verify(t, inputs)
		require.ErrorIs(t, err, collateral.ErrNotFound)
		require.ErrorContains(t, err, `container "app" requires provenance`)
	})
	t.Run("in full, no requirement", func(t *testing.T) {
		config, err := verify(t, embeddedInputs(t))
		require.NoError(t, err)
		require.Empty(t, config.Containers)
	})
	t.Run("in full, requirement the verifier cannot read", func(t *testing.T) {
		inputs, _ := requiring(t)
		inputs.Config.Bytes = append(inputs.Config.Bytes, []byte("      gitlab: {}\n")...)
		_, err := newEmbeddedVerifier(inputs)
		require.ErrorContains(t, err, `provenance has unknown field "gitlab"`)
	})
	t.Run("by reference, document carries the bytes, proven", func(t *testing.T) {
		inputs, config := requiring(t)
		verified, err := verify(t, byReference(t, inputs), configEntry(t, config), recordedContainerProof(t, recordedContainerDigest))
		require.NoError(t, err)
		require.Equal(t, proven, verified.Containers)
	})
	t.Run("by reference, document carries the bytes, proof missing", func(t *testing.T) {
		inputs, config := requiring(t)
		_, err := verify(t, byReference(t, inputs), configEntry(t, config))
		require.ErrorIs(t, err, collateral.ErrNotFound)
	})
	t.Run("by reference, document carries no bytes", func(t *testing.T) {
		inputs, _ := requiring(t)
		config, err := verify(t, byReference(t, inputs))
		require.NoError(t, err)
		require.Empty(t, config.Containers)
	})
	t.Run("by reference, document carries another config", func(t *testing.T) {
		inputs, config := requiring(t)
		other := append(bytes.Clone(config), '\n')
		verified, err := verify(t, byReference(t, inputs), configEntry(t, other))
		require.NoError(t, err)
		require.Empty(t, verified.Containers)
	})
}

func TestConfigVerificationOwnsItsContainers(t *testing.T) {
	v := &Verification{config: &ConfigVerification{Containers: []ContainerVerification{{Container: "app"}}}}
	config, ok := v.Config()
	require.True(t, ok)
	config.Containers[0].Container = "changed"
	config, _ = v.Config()
	require.Equal(t, "app", config.Containers[0].Container)
}
