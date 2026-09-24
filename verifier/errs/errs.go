// Package errs defines the SDK's three error categories. Wrapping preserves
// an existing category and the underlying cause, as in the JS SDK's wrapOrThrow.
//
// The categories live in this leaf package so that the low-level verification
// packages (document, quote, quote/sev, quote/tdx) can classify their errors
// without importing verifier, which imports them in turn. Callers should use
// the aliases re-exported from verifier.
package errs

import (
	"errors"
	"fmt"
)

// Error identifies an SDK error; upstream API errors retain their own types.
type Error interface {
	error
	Unwrap() error
	tinfoilError()
}

// ConfigurationError reports invalid caller arguments or client configuration.
type ConfigurationError struct{ Err error }

func (e *ConfigurationError) Error() string { return fmt.Sprintf("configuration error: %v", e.Err) }
func (e *ConfigurationError) Unwrap() error { return e.Err }
func (*ConfigurationError) tinfoilError()   {}

// FetchError reports failure to fetch attestation material.
type FetchError struct{ Err error }

func (e *FetchError) Error() string { return fmt.Sprintf("fetch error: %v", e.Err) }
func (e *FetchError) Unwrap() error { return e.Err }
func (*FetchError) tinfoilError()   {}

// AttestationError reports rejected evidence, policy, or channel binding.
type AttestationError struct{ Err error }

func (e *AttestationError) Error() string { return fmt.Sprintf("attestation error: %v", e.Err) }
func (e *AttestationError) Unwrap() error { return e.Err }
func (*AttestationError) tinfoilError()   {}

// WrapFetch wraps err unless it is nil or already contains an SDK error.
func WrapFetch(err error) error {
	if err == nil || classified(err) {
		return err
	}
	return &FetchError{Err: err}
}

// WrapAttestation wraps err unless it is nil or already contains an SDK error.
func WrapAttestation(err error) error {
	if err == nil || classified(err) {
		return err
	}
	return &AttestationError{Err: err}
}

func classified(err error) bool {
	var sdkError Error
	return errors.As(err, &sdkError)
}
