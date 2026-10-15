package verify

import "github.com/tinfoilsh/tinfoil-go/internal/errs"

// Error identifies an SDK error; upstream API errors retain their own types.
type Error = errs.Error

// ConfigurationError reports invalid caller arguments or client configuration.
type ConfigurationError = errs.ConfigurationError

// AttestationError reports rejected evidence, policy, or channel binding.
type AttestationError = errs.AttestationError
