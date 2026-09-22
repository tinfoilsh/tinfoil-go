package tinfoil

import "github.com/tinfoilsh/tinfoil-go/verifier"

// SDK error categories support errors.As; their causes support errors.Is.
type (
	Error              = verifier.Error
	ConfigurationError = verifier.ConfigurationError
	FetchError         = verifier.FetchError
	AttestationError   = verifier.AttestationError
)
