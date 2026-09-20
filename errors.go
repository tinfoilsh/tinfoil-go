package tinfoil

import "github.com/tinfoilsh/tinfoil-go/verifier/client"

// SDK error categories support errors.As; their causes support errors.Is.
type (
	Error              = client.Error
	ConfigurationError = client.ConfigurationError
	FetchError         = client.FetchError
	AttestationError   = client.AttestationError
)
