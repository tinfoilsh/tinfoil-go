package enclave

import "github.com/tinfoilsh/tinfoil-go/verify"

// SDK error categories support errors.As; their causes support errors.Is.
type (
	Error              = verify.Error
	ConfigurationError = verify.ConfigurationError
	FetchError         = verify.FetchError
	AttestationError   = verify.AttestationError
)
