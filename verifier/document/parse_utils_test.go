package document

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeLowerHex(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantLen int
		want    []byte
		wantErr string
	}{
		{name: "valid", value: "00ff10ab", wantLen: 4, want: []byte{0x00, 0xff, 0x10, 0xab}},
		{name: "valid 32 bytes", value: strings.Repeat("a5", 32), wantLen: 32, want: bytes.Repeat([]byte{0xa5}, 32)},
		{name: "empty with zero length", value: "", wantLen: 0, want: []byte{}},
		{name: "empty with nonzero length", value: "", wantLen: 32, wantErr: "field must be 32 bytes, got 0"},
		{name: "too short", value: "aabb", wantLen: 3, wantErr: "field must be 3 bytes, got 2"},
		{name: "too long", value: "aabbccdd", wantLen: 3, wantErr: "field must be 3 bytes, got 4"},
		{name: "uppercase", value: "AABB", wantLen: 2, wantErr: "field is not lowercase hex"},
		{name: "mixed case", value: "aAbb", wantLen: 2, wantErr: "field is not lowercase hex"},
		{name: "non-hex letter", value: "aagg", wantLen: 2, wantErr: "field is not lowercase hex"},
		{name: "0x prefix", value: "0xaabb", wantLen: 3, wantErr: "field is not lowercase hex"},
		{name: "leading space", value: " aabb", wantLen: 2, wantErr: "field is not lowercase hex"},
		{name: "trailing newline", value: "aabb\n", wantLen: 2, wantErr: "field is not lowercase hex"},
		{name: "embedded newline", value: "aa\nbb", wantLen: 2, wantErr: "field is not lowercase hex"},
		{name: "fullwidth digits", value: "００", wantLen: 1, wantErr: "field is not lowercase hex"},
		// Odd length passes the character class but is not decodable.
		{name: "odd length", value: "abc", wantLen: 1, wantErr: "field is not hex"},
		{name: "single character", value: "a", wantLen: 0, wantErr: "field is not hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeLowerHex("field", tt.value, tt.wantLen)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDecodeLowerHexRoundTrip(t *testing.T) {
	for n := 0; n <= 64; n++ {
		b := make([]byte, n)
		_, err := rand.Read(b)
		require.NoError(t, err)
		got, err := decodeLowerHex("field", hex.EncodeToString(b), n)
		require.NoError(t, err, "length %d", n)
		assert.Equal(t, b, got, "length %d", n)
	}
}

func TestDecodeCanonicalBase64(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []byte
		wantErr string
	}{
		{name: "empty", value: "", want: []byte{}},
		{name: "no padding needed", value: "YWJj", want: []byte("abc")},
		{name: "one pad", value: "YWI=", want: []byte("ab")},
		{name: "two pads", value: "YQ==", want: []byte("a")},
		{name: "plus and slash", value: "+/+/", want: []byte{0xfb, 0xff, 0xbf}},
		{name: "missing padding", value: "YQ", wantErr: "decoding field"},
		{name: "extra padding", value: "YQ===", wantErr: "decoding field"},
		{name: "padding in middle", value: "YQ==YWJj", wantErr: "decoding field"},
		// Strict rejects non-zero trailing bits, which would otherwise give
		// "YR==" and "YQ==" the same decoding.
		{name: "nonzero padding bits", value: "YR==", wantErr: "decoding field"},
		{name: "url-safe alphabet", value: "-_-_", wantErr: "decoding field"},
		{name: "space", value: "YW Jj", wantErr: "decoding field"},
		{name: "invalid character", value: "YW*j", wantErr: "decoding field"},
		// The decoder skips \r and \n, so only the round-trip check catches these.
		{name: "embedded newline", value: "YW\nJj", wantErr: "field is not canonical base64"},
		{name: "embedded carriage return", value: "YW\rJj", wantErr: "field is not canonical base64"},
		{name: "trailing newline", value: "YWJj\n", wantErr: "field is not canonical base64"},
		{name: "leading CRLF", value: "\r\nYWJj", wantErr: "field is not canonical base64"},
		{name: "only newlines", value: "\n\n", wantErr: "field is not canonical base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeCanonicalBase64("field", tt.value)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDecodeCanonicalBase64RoundTrip(t *testing.T) {
	for n := 0; n <= 64; n++ {
		b := make([]byte, n)
		_, err := rand.Read(b)
		require.NoError(t, err)
		got, err := decodeCanonicalBase64("field", base64.StdEncoding.EncodeToString(b))
		require.NoError(t, err, "length %d", n)
		assert.Equal(t, b, got, "length %d", n)
	}
}
