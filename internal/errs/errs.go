// Package errs defines the SDK's error type and its three categories.
// Wrapping preserves an existing category and the underlying cause, as in the
// JS SDK's wrapOrThrow.
//
// They live in this leaf package so that internal/fetch can classify its
// errors without importing enclave, which imports it in turn. Callers should
// use the names re-exported from tinfoil. Package verify has error types of
// its own, which enclave reports in these categories.
package errs

import (
	"errors"
	"fmt"
)

// The categories of an Error, which errors.Is reports.
var (
	// ErrConfiguration reports invalid caller arguments or client
	// configuration.
	ErrConfiguration = errors.New("configuration error")
	// ErrNetwork reports that the client couldn't reach what it needed: a
	// network failure, a timeout or an HTTP error status while fetching
	// attestation material, or a gateway that keeps routing a request away
	// from its enclave.
	ErrNetwork = errors.New("network error")
	// ErrAttestation reports rejected evidence, policy, or channel binding.
	ErrAttestation = errors.New("attestation error")
)

// Error is an SDK error: one of the categories and the error that caused it.
// errors.Is reports both, and errors.As finds the cause's types. Use them
// rather than errors.Unwrap, which can't follow an error with two parts.
// Upstream API errors keep their own types.
type Error struct {
	category error
	// Err is the cause.
	Err error
}

func (e *Error) Error() string   { return fmt.Sprintf("%v: %v", e.category, e.Err) }
func (e *Error) Unwrap() []error { return []error{e.category, e.Err} }

// Configuration returns err as a configuration error.
func Configuration(err error) error { return &Error{category: ErrConfiguration, Err: err} }

// Network returns err as a network error.
func Network(err error) error { return &Error{category: ErrNetwork, Err: err} }

// Attestation returns err as an attestation error.
func Attestation(err error) error { return &Error{category: ErrAttestation, Err: err} }

// WrapNetwork wraps err unless it is nil or already contains an SDK error.
func WrapNetwork(err error) error {
	if err == nil || classified(err) {
		return err
	}
	return Network(err)
}

// WrapAttestation wraps err unless it is nil or already contains an SDK error.
func WrapAttestation(err error) error {
	if err == nil || classified(err) {
		return err
	}
	return Attestation(err)
}

func classified(err error) bool {
	var sdkError *Error
	return errors.As(err, &sdkError)
}
