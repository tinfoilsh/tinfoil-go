package client

import (
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"fmt"
)

// NewSecureClientWithOptionsJSON is the gomobile adapter for NewSecureClientWithOptions.
// optionsJSON encodes VerificationOptions, with freshness_max_age_ns in nanoseconds.
func NewSecureClientWithOptionsJSON(enclave, repo, optionsJSON string) (*SecureClient, error) {
	opts, err := parseVerificationOptionsJSON(optionsJSON)
	if err != nil {
		return nil, err
	}
	return NewSecureClientWithOptions(enclave, repo, opts)
}

// NewDefaultClientWithOptionsJSON applies JSON-encoded VerificationOptions to
// every discovered router and fallback. Use {} for the default policy.
func NewDefaultClientWithOptionsJSON(optionsJSON string) (*SecureClient, error) {
	opts, err := parseVerificationOptionsJSON(optionsJSON)
	if err != nil {
		return nil, err
	}
	return NewDefaultClientWithOptions(opts)
}

// VerifyDocumentV3WithOptionsJSON accepts JSON-encoded VerificationOptions and
// returns VerifiedDocumentV3 as JSON, including FreshnessExpiresAt in RFC3339 format.
// Callers must bind traffic to the returned keys and enforce that deadline.
func VerifyDocumentV3WithOptionsJSON(docBytes, nonce []byte, repo, optionsJSON string) (string, error) {
	opts, err := parseVerificationOptionsJSON(optionsJSON)
	if err != nil {
		return "", err
	}
	verified, err := VerifyDocumentV3WithOptions(docBytes, nonce, repo, opts)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(verified)
	return string(encoded), err
}

func parseVerificationOptionsJSON(raw string) (VerificationOptions, error) {
	var opts *VerificationOptions
	if err := json.Unmarshal([]byte(raw), &opts, json.RejectUnknownMembers(true), jsonv1.FormatDurationAsNano(true)); err != nil {
		return VerificationOptions{}, fmt.Errorf("parsing verification options: %w", err)
	}
	if opts == nil {
		return VerificationOptions{}, fmt.Errorf("verification options must be a JSON object")
	}
	return *opts, nil
}
