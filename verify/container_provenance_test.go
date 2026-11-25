package verify

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
)

// The recorded bundle is the published build attestation of the image with
// this digest, and meets recordedContainerProvenance.
const (
	recordedContainerBundle     = "internal/endorsement/testdata/container-provenance-bundle.json"
	recordedContainerDigest     = "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1"
	recordedContainerProvenance = `{"github":{"repository":"tinfoilsh/measure-image-action","repository_id":"924941172","workflow":"build.yml","ref":"refs/tags/build-v0.14.2","commit":"01a05df207140a8e8e1d2cd26028ab7c51dad9d1"}}`
)

// requiringProvenance returns config with a container that runs the recorded
// image under the given provenance member.
func requiringProvenance(config []byte, provenance string) []byte {
	return []byte(strings.TrimSuffix(string(config), "}") + `,"containers":[{"name":"app","image":"ghcr.io/tinfoilsh/measure-image-action@sha256:` + recordedContainerDigest + `","provenance":` + provenance + `}]}`)
}

func configEntry(t *testing.T, config []byte) collateral.Entry {
	t.Helper()
	data, err := json.Marshal(map[string][]byte{"config_base64": config})
	require.NoError(t, err)
	return collateral.Entry{ID: collateral.ConfigID, Role: collateral.RoleReferenceValues, Format: collateral.ConfigV1Format, Data: data}
}

// A document here has no authentic quote, so one whose provenance passes is
// rejected at the quote layer.
func TestContainerProvenance(t *testing.T) {
	inputs := embeddedInputs(t)
	plain := inputs.Config.Bytes
	requiring := requiringProvenance(plain, recordedContainerProvenance)
	unreadable := requiringProvenance(plain, `{"gitlab":{}}`)
	authorizer := ConfigAuthorizer{Authorize: func(collateral.ConfigEndorsement) error { return nil }}
	embedded := EmbeddedConfig{Bytes: requiring}
	reference, err := embedded.reference()
	require.NoError(t, err)

	bundle, err := os.ReadFile(recordedContainerBundle)
	require.NoError(t, err)
	data, err := json.Marshal(map[string]any{"digest": recordedContainerDigest, "sigstore_bundle": jsontext.Value(bundle)})
	require.NoError(t, err)
	proof := collateral.Entry{ID: "container:sha256:" + recordedContainerDigest, Role: collateral.RoleReferenceValues, Format: collateral.ContainerProvenanceV1Format, Data: data}

	for name, tt := range map[string]struct {
		config  ConfigTrust
		entries []collateral.Entry
		want    Layer
	}{
		"authorized, proven":                    {authorizer, []collateral.Entry{configEntry(t, requiring), proof}, LayerQuote},
		"authorized, no entry":                  {authorizer, []collateral.Entry{configEntry(t, requiring)}, LayerProvenance},
		"authorized, another workflow":          {authorizer, []collateral.Entry{configEntry(t, requiringProvenance(plain, strings.Replace(recordedContainerProvenance, "build.yml", "release.yml", 1))), proof}, LayerProvenance},
		"authorized, unknown kind":              {authorizer, []collateral.Entry{configEntry(t, unreadable), proof}, LayerProvenance},
		"embedded, proven":                      {embedded, []collateral.Entry{proof}, LayerQuote},
		"embedded, no entry":                    {embedded, nil, LayerProvenance},
		"embedded, unknown kind":                {EmbeddedConfig{Bytes: unreadable}, []collateral.Entry{proof}, LayerProvenance},
		"reference, document's bytes, proven":   {reference, []collateral.Entry{configEntry(t, requiring), proof}, LayerQuote},
		"reference, document's bytes, no entry": {reference, []collateral.Entry{configEntry(t, requiring)}, LayerProvenance},
		"reference, no bytes":                   {reference, nil, LayerQuote},
		"reference, bytes of another config":    {reference, []collateral.Entry{configEntry(t, unreadable)}, LayerQuote},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := NewVerifier(tt.config, inputs.policy())
			require.NoError(t, err)
			raw, nonce, _ := embeddedDocument(t, collateral.FormatV3, tt.entries...)
			_, err = v.VerifyV3(raw, nonce, Pin{})
			requireRejectedAt(t, err, tt.want)
		})
	}
}
