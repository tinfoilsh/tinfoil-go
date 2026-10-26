// Package errs defines the SDK's three error categories. Wrapping preserves
// an existing category and the underlying cause, as in the JS SDK's wrapOrThrow.
//
// The categories live in this leaf package so that internal/fetch can classify
// its errors without importing enclave, which imports it in turn. Callers
// should use the aliases re-exported from tinfoil. Package verify
// has error types of its own, which enclave reports in these categories.
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

// NetworkError reports that the client couldn't reach what it needed: a network
// failure, a timeout or an HTTP error status while fetching attestation
// material, or a gateway that keeps routing a request away from its enclave.
type NetworkError struct{ Err error }

func (e *NetworkError) Error() string { return fmt.Sprintf("network error: %v", e.Err) }
func (e *NetworkError) Unwrap() error { return e.Err }
func (*NetworkError) tinfoilError()   {}

// AttestationError reports rejected evidence, policy, or channel binding.
type AttestationError struct{ Err error }

func (e *AttestationError) Error() string { return fmt.Sprintf("attestation error: %v", e.Err) }
func (e *AttestationError) Unwrap() error { return e.Err }
func (*AttestationError) tinfoilError()   {}

// WrapNetwork wraps err unless it is nil or already contains an SDK error.
func WrapNetwork(err error) error {
	if err == nil || classified(err) {
		return err
	}
	return &NetworkError{Err: err}
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
