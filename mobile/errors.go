package mobile

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// An error crosses the FFI as its message alone, so its type is read from the
// prefix this package gives it. These are the prefixes; any other message is
// an error outside the two types.
const (
	// UsageErrorPrefix leads an error in the caller's arguments or options.
	// Retrying will not help.
	UsageErrorPrefix = "usage error: "
	// VerificationErrorPrefix leads a document that must not be trusted. The
	// layer that rejected it comes next, then ": " and the detail, as in
	// "verification error: quote: <detail>".
	VerificationErrorPrefix = "verification error: "
)

// toMobileError gives err the message Swift reads: its type's prefix, the
// layer for a verification error, then the message with the type's own text
// reduced to its cause. The prefix comes from err's type rather than its
// text, so the Go error types can word their messages freely without changing
// what Swift matches on.
func toMobileError(err error) error {
	// Verification reports verify's types, the outermost deciding the type;
	// option parsing and AttestationURL report the SDK's configuration error,
	// which is the caller's mistake too.
	var classified verify.Error
	var configuration *enclave.ConfigurationError
	var category, cause error
	var prefix string
	switch {
	case errors.As(err, &classified):
		category, cause, prefix = classified, classified.Unwrap(), UsageErrorPrefix
		if rejected, ok := classified.(*verify.VerificationError); ok {
			prefix = VerificationErrorPrefix + string(rejected.Layer) + ": "
		}
	case errors.As(err, &configuration):
		category, cause, prefix = configuration, configuration.Err, UsageErrorPrefix
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
