package enclave

import "github.com/tinfoilsh/tinfoil-go/internal/errs"

// SDK error categories support errors.As; their causes support errors.Is.
type (
	Error              = errs.Error
	ConfigurationError = errs.ConfigurationError
	FetchError         = errs.FetchError
	AttestationError   = errs.AttestationError
)
