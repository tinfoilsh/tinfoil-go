package enclave

import (
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
)

// HTTP adds context outside the SDK category. Restore its leading prefix for
// gomobile without replacing the category or losing the HTTP error's cause.
// The wrapped message already holds the category's own, so its prefix moves to
// the front rather than appearing twice.
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
	message := err.Error()
	if strings.HasPrefix(message, prefix) {
		return err
	}
	own := category.Error()
	message = strings.Replace(message, own, strings.TrimPrefix(own, prefix), 1)
	return &prefixedError{message: prefix + message, err: err}
}

type prefixedError struct {
	message string
	err     error
}

func (e *prefixedError) Error() string { return e.message }
func (e *prefixedError) Unwrap() error { return e.err }

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
