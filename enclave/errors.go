package enclave

import (
	"errors"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// SDK error categories support errors.As; their causes support errors.Is.
type (
	Error              = errs.Error
	ConfigurationError = errs.ConfigurationError
	FetchError         = errs.FetchError
	AttestationError   = errs.AttestationError
)

// fromVerify reports a verify error in the SDK's categories: a UsageError is
// the caller's configuration error, and anything else verify rejects is an
// attestation failure. The verify error remains the cause.
func fromVerify(err error) error {
	var usage *verify.UsageError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &usage):
		return &ConfigurationError{Err: err}
	default:
		return &AttestationError{Err: err}
	}
}
