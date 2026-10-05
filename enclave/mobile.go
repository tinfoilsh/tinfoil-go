package enclave

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

// ParseOptionsJSON decodes policy for use with the Go and mobile APIs.
// Use {} for defaults. Freshness age is encoded in integer nanoseconds.
func ParseOptionsJSON(raw string) (*Options, error) {
	var opts *Options
	if err := json.Unmarshal([]byte(raw), &opts, json.RejectUnknownMembers(true), jsonv1.FormatDurationAsNano(true)); err != nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("parsing verification options: %w", err)}
	}
	if opts == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("verification options must be a JSON object")}
	}
	return opts, nil
}
