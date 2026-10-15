package mobile

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// An error crosses the FFI as its message alone, so its category is read from
// the prefix this package gives it. These are the prefixes; any other message
// is an error outside the two categories.
const (
	// ConfigurationErrorPrefix leads an error in the caller's arguments or
	// options. Retrying will not help.
	ConfigurationErrorPrefix = "configuration error: "
	// AttestationErrorPrefix leads rejected evidence, policy or channel binding.
	AttestationErrorPrefix = "attestation error: "
)

// toMobileError gives err the message Swift reads: its category's prefix, then
// the message with the category's own text reduced to its cause. The prefix
// comes from err's type rather than its text, so the Go error types can word
// their messages freely without changing what Swift matches on.
func toMobileError(err error) error {
	var configuration *verify.ConfigurationError
	var attestation *verify.AttestationError
	var category, cause error
	var prefix string
	switch {
	case errors.As(err, &configuration):
		category, cause, prefix = configuration, configuration.Err, ConfigurationErrorPrefix
	case errors.As(err, &attestation):
		category, cause, prefix = attestation, attestation.Err, AttestationErrorPrefix
	default:
		return err
	}
	message := strings.Replace(err.Error(), category.Error(), fmt.Sprint(cause), 1)
	return &mobileError{message: prefix + message, err: err}
}

type mobileError struct {
	message string
	err     error
}

func (e *mobileError) Error() string { return e.message }
func (e *mobileError) Unwrap() error { return e.err }
