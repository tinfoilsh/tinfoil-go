// Package errors defines the SDK's three error categories. Wrapping preserves
// an existing category and the underlying cause, as in the JS SDK's wrapOrThrow.
package errors

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

// Configuration classifies err unless it is nil or already an SDK error.
func Configuration(err error) error {
	if err == nil || classified(err) {
		return err
	}
	return &ConfigurationError{Err: err}
}

// Fetch classifies err unless it is nil or already an SDK error.
func Fetch(err error) error {
	if err == nil || classified(err) {
		return err
	}
	return &FetchError{Err: err}
}

// Attestation classifies err unless it is nil or already an SDK error.
func Attestation(err error) error {
	if err == nil || classified(err) {
		return err
	}
	return &AttestationError{Err: err}
}

func classified(err error) bool {
	var sdkError Error
	return errors.As(err, &sdkError)
}
