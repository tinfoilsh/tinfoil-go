package verify

import (
	"errors"
	"fmt"
)

// Error identifies an error returned by this package: a UsageError or a
// VerificationError.
type Error interface {
	error
	Unwrap() error
	verifyError()
}

// UsageError reports a verifier built or called with invalid inputs. Fix the
// caller; retrying will not help.
type UsageError struct{ Err error }

func (e *UsageError) Error() string { return fmt.Sprintf("usage error: %v", e.Err) }
func (e *UsageError) Unwrap() error { return e.Err }
func (*UsageError) verifyError()    {}

// VerificationError reports a document that must not be trusted.
type VerificationError struct{ Err error }

func (e *VerificationError) Error() string { return fmt.Sprintf("verification error: %v", e.Err) }
func (e *VerificationError) Unwrap() error { return e.Err }
func (*VerificationError) verifyError()    {}

// wrapVerification wraps err unless it is nil or already contains a verify
// error.
func wrapVerification(err error) error {
	var classified Error
	if err == nil || errors.As(err, &classified) {
		return err
	}
	return &VerificationError{Err: err}
}
