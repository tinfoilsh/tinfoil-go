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
	NetworkError       = errs.NetworkError
	AttestationError   = errs.AttestationError
)

// fromVerify reports a verify error in the SDK's categories by its outermost
// verify type: a UsageError is the caller's configuration error, and anything
// else verify rejects is an attestation failure. The verify error remains the
// cause.
func fromVerify(err error) error {
	if err == nil {
		return nil
	}
	var classified verify.Error
	if errors.As(err, &classified) {
		if _, usage := classified.(*verify.UsageError); usage {
			return &ConfigurationError{Err: err}
		}
	}
	return &AttestationError{Err: err}
}
