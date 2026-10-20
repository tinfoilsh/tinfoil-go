package mobile

import (
	"errors"
	"fmt"
	"strings"

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
	// The outermost verify error decides the type.
	var classified verify.Error
	if !errors.As(err, &classified) {
		return err
	}
	prefix := UsageErrorPrefix
	if rejected, ok := classified.(*verify.VerificationError); ok {
		prefix = VerificationErrorPrefix + string(rejected.Layer) + ": "
	}
	message := strings.Replace(err.Error(), classified.Error(), fmt.Sprint(classified.Unwrap()), 1)
	return &mobileError{message: prefix + message, err: err}
}

type mobileError struct {
	message string
	err     error
}

func (e *mobileError) Error() string { return e.message }
func (e *mobileError) Unwrap() error { return e.err }
