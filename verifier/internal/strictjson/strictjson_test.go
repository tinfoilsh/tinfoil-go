package strictjson

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
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
		"surrogate pair":        `{"format":"\uD83D\uDE00","blob":"\uD83D\uDE00"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out strictOuter
			assert.NoError(t, Unmarshal([]byte(input), &out))
		})
	}
}

func TestStrictUnmarshalRejects(t *testing.T) {
	for name, input := range map[string]string{
		"case-mismatched member":     `{"FORMAT":"f"}`,
		"untagged field exact case":  `{"labels":{}}`,
		"unknown member":             `{"extra":1}`,
		"duplicate member":           `{"format":"a","format":"b"}`,
		"duplicate in nested struct": `{"items":[{"id":"a","id":"b"}]}`,
		"duplicate inside raw blob":  `{"blob":{"k":1,"k":2}}`,
		"duplicate in map":           `{"Labels":{"k":["a"],"k":["b"]}}`,
		"invalid utf-8":              "{\"format\":\"\xff\"}",
		"trailing data":              `{"format":"f"} {}`,
		"lone high surrogate":        `{"format":"\uD800"}`,
		"lone low surrogate":         `{"format":"\uDC00"}`,
		"high surrogate in raw blob": `{"blob":{"k":"\uD800"}}`,
		"low surrogate in raw blob":  `{"blob":{"k":"\uDC00"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var out strictOuter
			assert.Error(t, Unmarshal([]byte(input), &out))
		})
	}
}
