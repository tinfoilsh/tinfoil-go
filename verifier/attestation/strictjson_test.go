package attestation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type strictOuter struct {
	Format string          `json:"format"`
	Items  []strictItem    `json:"items"`
	Blob   json.RawMessage `json:"blob"`
	Labels map[string][]string
	hidden string //nolint:unused // exercises unexported-field skipping
}

type strictItem struct {
	ID string `json:"id"`
}

func TestStrictUnmarshalAccepts(t *testing.T) {
	for name, input := range map[string]string{
		"basic":                 `{"format":"f","items":[{"id":"a"},{"id":"b"}]}`,
		"raw camelCase members": `{"blob":{"mediaType":"x","verificationMaterial":{"tlogEntries":[]}}}`,
		"map keys are data":     `{"Labels":{"Content-Type":["a"],"content-type":["b"]}}`,
		"null members":          `{"format":null,"items":null,"blob":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out strictOuter
			assert.NoError(t, strictUnmarshal([]byte(input), &out))
		})
	}
}

func TestStrictUnmarshalRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		input   string
		wantErr string
	}{
		"case-mismatched member":     {`{"FORMAT":"f"}`, `unknown object member "FORMAT"`},
		"untagged field exact case":  {`{"labels":{}}`, `unknown object member "labels"`},
		"unknown member":             {`{"extra":1}`, `unknown object member "extra"`},
		"duplicate member":           {`{"format":"a","format":"b"}`, `duplicate object member "format"`},
		"duplicate in nested struct": {`{"items":[{"id":"a","id":"b"}]}`, `duplicate object member "id"`},
		"duplicate inside raw blob":  {`{"blob":{"k":1,"k":2}}`, `duplicate object member "k"`},
		"duplicate in map":           {`{"Labels":{"k":["a"],"k":["b"]}}`, `duplicate object member "k"`},
		"invalid utf-8":              {"{\"format\":\"\xff\"}", "not valid UTF-8"},
		"trailing data":              {`{"format":"f"} {}`, "trailing data"},
	} {
		t.Run(name, func(t *testing.T) {
			var out strictOuter
			err := strictUnmarshal([]byte(tc.input), &out)
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestDecodeCanonicalBase64(t *testing.T) {
	got, err := decodeCanonicalBase64("field", "ZQ==")
	require.NoError(t, err)
	assert.Equal(t, []byte("e"), got)

	// Non-zero trailing padding bits: decodes to the same byte under the
	// default decoder, must be rejected here.
	_, err = decodeCanonicalBase64("field", "ZR==")
	assert.Error(t, err)

	// Embedded newline: the default and Strict decoders both skip it, so
	// only the canonical round-trip catches it.
	_, err = decodeCanonicalBase64("field", "Z\nQ==")
	assert.ErrorContains(t, err, "not canonical base64")

	_, err = decodeCanonicalBase64("field", "ZQ")
	assert.Error(t, err, "missing padding must be rejected")
}
