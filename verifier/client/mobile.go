package client

import (
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"fmt"
)

// ParseVerificationOptionsJSON decodes policy for use with the Go and mobile APIs.
// Use {} for defaults. Freshness age is encoded in integer nanoseconds.
func ParseVerificationOptionsJSON(raw string) (*VerificationOptions, error) {
	var opts *VerificationOptions
	if err := json.Unmarshal([]byte(raw), &opts, json.RejectUnknownMembers(true), jsonv1.FormatDurationAsNano(true)); err != nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("parsing verification options: %w", err)}
	}
	if opts == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("verification options must be a JSON object")}
	}
	return opts, nil
}

// VerifyDocumentV3JSON returns the verified keys, measurements, and witness deadline.
// Callers must bind traffic to the keys and enforce FreshnessExpiresAt.
func VerifyDocumentV3JSON(docBytes, nonce []byte, repo string, opts *VerificationOptions) (string, error) {
	verified, err := VerifyDocumentV3(docBytes, nonce, repo, opts)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(verified)
	return string(encoded), err
}
