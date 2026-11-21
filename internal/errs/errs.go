// Package errs defines the SDK's error type and its three categories.
//
// An error is classified where its meaning is known: at the check that fails,
// or at the adapter around a component outside the SDK, such as the verifier,
// the HTTP stack or a caller's callback. A layer that only passes an error
// along may add context with fmt.Errorf and %w, but it never classifies the
// error again. Every public entry point ends with Finish, which gives an error
// that no layer classified its category and leaves every other error as it
// is, so that the caller finds exactly one category.
//
// They live in this leaf package so that internal/fetch can classify its
// errors without importing enclave, which imports it in turn. Callers should
// use the names re-exported from tinfoil. Package verify has error types of
// its own, which enclave reports in these categories.
package errs

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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

// categories are the three categories, in the order that messages name them.
var categories = [...]error{ErrConfiguration, ErrNetwork, ErrAttestation}

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

// WrapNetwork returns err as a network error unless it is nil or already
// carries a category, which it keeps. It is for an adapter whose foreign
// component may report an SDK error of its own, as a caller's attestation
// fetcher may.
func WrapNetwork(err error) error {
	if err == nil || categorized(err) {
		return err
	}
	return Network(err)
}

// WrapAttestation returns err as an attestation error unless it is nil or
// already carries a category, which it keeps.
func WrapAttestation(err error) error {
	if err == nil || categorized(err) {
		return err
	}
	return Attestation(err)
}

// Finish is the backstop that every public entry point and transport hook
// applies to the error that it returns. ctx is the context that the caller
// passed in, and err is the error of work done under ctx or under a context
// that the SDK derived from it. Finish returns:
//
//   - err as it is when it already carries a category, so that no error is
//     classified twice;
//   - err as it is when the work stopped because ctx ended, that is, when ctx
//     is done and err matches ctx.Err() with errors.Is, so that the caller's
//     cancellation passes through;
//   - err as a network error otherwise. This includes a timeout that the SDK
//     imposes on a context that it derived from ctx, and a failure that came
//     before the caller cancelled.
//
// Finish(ctx, Finish(ctx, err)) is Finish(ctx, err), and Finish(ctx, nil) is
// nil. A leaf that owns a derived context, such as a fetch with its own time
// limit, classifies its errors with Finish under the caller's context too.
func Finish(ctx context.Context, err error) error {
	if err == nil || categorized(err) {
		return err
	}
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
		return err
	}
	return Network(err)
}

// Uncategorized returns err without the categories that it carries, for an
// adapter that classifies the error of a component outside the SDK, such as a
// caller's callback, which can return an SDK error of its own. The result has
// err's message, and errors.Is and errors.As reach err and every error in its
// chain except the SDK errors and categories in it, whose causes they still
// reach. The adapter's category is then the only one. An err that carries no
// category is returned as it is.
func Uncategorized(err error) error {
	if err == nil || !categorized(err) {
		return err
	}
	return &uncategorized{err}
}

// uncategorized is a view of an error's chain without the SDK errors and
// categories in it. Each error in the chain appears as a view of its own,
// which reports the error itself to errors.Is and errors.As through its Is
// and As methods.
type uncategorized struct{ err error }

func (u *uncategorized) Error() string { return u.err.Error() }

// Unwrap returns views of the errors that u.err wraps: an SDK error is
// replaced by its cause, and a category is left out.
func (u *uncategorized) Unwrap() []error {
	var next []error
	switch e := u.err.(type) {
	case *Error:
		next = []error{e.Err}
	case interface{ Unwrap() error }:
		next = []error{e.Unwrap()}
	case interface{ Unwrap() []error }:
		next = e.Unwrap()
	}
	views := make([]error, 0, len(next))
	for _, n := range next {
		if n != nil && !isCategory(n) {
			views = append(views, &uncategorized{n})
		}
	}
	return views
}

// Is reports whether u.err is target, or its Is method says so. It reports
// neither an SDK error, which the view replaces by its cause, nor a category.
func (u *uncategorized) Is(target error) bool {
	if u.hidden() {
		return false
	}
	if reflect.TypeOf(target) != nil && reflect.TypeOf(target).Comparable() && u.err == target {
		return true
	}
	is, ok := u.err.(interface{ Is(error) bool })
	return ok && is.Is(target)
}

// As sets target to u.err when u.err is assignable to it, as errors.As does
// for each error in a chain, or defers to u.err's As method. It reports
// neither an SDK error nor a category.
func (u *uncategorized) As(target any) bool {
	if u.hidden() {
		return false
	}
	// errors.As has checked that target is a non-nil pointer.
	dst := reflect.ValueOf(target).Elem()
	if reflect.TypeOf(u.err).AssignableTo(dst.Type()) {
		dst.Set(reflect.ValueOf(u.err))
		return true
	}
	as, ok := u.err.(interface{ As(any) bool })
	return ok && as.As(target)
}

// hidden reports whether u.err is an SDK error or a category, which the view
// doesn't report.
func (u *uncategorized) hidden() bool {
	_, ok := u.err.(*Error)
	return ok || isCategory(u.err)
}

// categorized reports whether err carries a category: whether it contains an
// SDK error, or one of the categories themselves.
func categorized(err error) bool {
	var sdkError *Error
	if errors.As(err, &sdkError) {
		return true
	}
	for _, c := range categories {
		if errors.Is(err, c) {
			return true
		}
	}
	return false
}

func isCategory(err error) bool {
	for _, c := range categories {
		if err == c {
			return true
		}
	}
	return false
}
