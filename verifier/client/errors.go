package client

import "github.com/tinfoilsh/tinfoil-go/internal/errdefs"

// SDK error categories support errors.As; their causes support errors.Is.
type (
	Error              = errdefs.Error
	ConfigurationError = errdefs.ConfigurationError
	FetchError         = errdefs.FetchError
	AttestationError   = errdefs.AttestationError
)
