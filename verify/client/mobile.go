package client

import (
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"errors"
	"fmt"
)

// HTTP adds context outside the SDK category. Restore its leading prefix for
// gomobile without replacing the category or losing the HTTP error's cause.
func mobileError(err error) error {
	var category Error
	if !errors.As(err, &category) || err == category {
		return err
	}
	var prefix string
	switch category.(type) {
	case *ConfigurationError:
		prefix = "configuration error: "
	case *FetchError:
		prefix = "fetch error: "
	case *AttestationError:
		prefix = "attestation error: "
	}
	return fmt.Errorf("%s%w", prefix, err)
}

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
