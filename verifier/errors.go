// Package verifier re-exports the SDK's three error categories. They are
// defined in verifier/errs so the low-level verification packages can classify
// their errors without importing this package, which imports them in turn.
package verifier

import "github.com/tinfoilsh/tinfoil-go/verifier/errs"

// Error identifies an SDK error; upstream API errors retain their own types.
type Error = errs.Error

// ConfigurationError reports invalid caller arguments or client configuration.
type ConfigurationError = errs.ConfigurationError

// FetchError reports failure to fetch attestation material.
type FetchError = errs.FetchError

// AttestationError reports rejected evidence, policy, or channel binding.
type AttestationError = errs.AttestationError

// WrapFetch wraps err unless it is nil or already contains an SDK error.
func WrapFetch(err error) error { return errs.WrapFetch(err) }

// WrapAttestation wraps err unless it is nil or already contains an SDK error.
func WrapAttestation(err error) error { return errs.WrapAttestation(err) }
