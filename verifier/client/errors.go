package client

import sdkerrors "github.com/tinfoilsh/tinfoil-go/verifier/errors"

// SDK error categories support errors.As; their causes support errors.Is.
type (
	Error              = sdkerrors.Error
	ConfigurationError = sdkerrors.ConfigurationError
	FetchError         = sdkerrors.FetchError
	AttestationError   = sdkerrors.AttestationError
)
