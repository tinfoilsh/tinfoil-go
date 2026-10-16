package verify

import "github.com/tinfoilsh/tinfoil-go/verify/internal/errs"

// Error identifies an error returned by this package: a UsageError or a
// VerificationError.
type Error = errs.Error

// UsageError reports a verifier built or called with invalid inputs. Fix the
// caller; retrying will not help.
type UsageError = errs.UsageError

// VerificationError reports a document that must not be trusted.
type VerificationError = errs.VerificationError
