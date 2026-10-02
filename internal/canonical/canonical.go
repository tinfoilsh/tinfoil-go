// Package canonical decodes the attestation document's binary field
// encodings, accepting exactly one encoding per byte string.
package canonical

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
)

var lowerHexRE = regexp.MustCompile(`^[0-9a-f]*$`)

// IsLowerHex reports whether s contains only lowercase hex digits. It does not
// check that s has even length.
func IsLowerHex(s string) bool {
	return lowerHexRE.MatchString(s)
}

// DecodeLowerHex decodes a required lowercase hex field of an exact byte length.
func DecodeLowerHex(name, value string, wantLen int) ([]byte, error) {
	if !IsLowerHex(value) {
		return nil, fmt.Errorf("%s is not lowercase hex", name)
	}
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %w", name, err)
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("%s must be %d bytes, got %d", name, wantLen, len(b))
	}
	return b, nil
}

// DecodeBase64 decodes a required standard-base64 field and rejects
// non-canonical encodings. Strict() rejects non-zero padding bits but still
// skips \r and \n, so the round-trip comparison is what guarantees exactly
// one accepted encoding per byte string.
func DecodeBase64(name, value string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", name, err)
	}
	if base64.StdEncoding.EncodeToString(b) != value {
		return nil, fmt.Errorf("%s is not canonical base64", name)
	}
	return b, nil
}
