package tinfoil

import "github.com/tinfoilsh/tinfoil-go/internal/errs"

// Error is an SDK error: one of the categories below and the error that
// caused it, in Err. errors.Is reports both the category and the cause, and
// errors.As finds the cause's types; errors.Unwrap can't follow an error with
// two parts, so use those instead. Its message is the category, ": ", then
// the cause, as in "attestation error: <cause>".
//
// Every error that the SDK returns, from a function or method of this
// package or from a request through one of its clients, is in exactly one
// category, with two exceptions that pass through in none: the caller's own
// cancellation, and an upstream API error, such as an *openai.Error, which
// keeps the wrapped library's type. Find the category with errors.Is, as in
// errors.Is(err, tinfoil.ErrAttestation), or the SDK error itself with
// errors.As into a *tinfoil.Error. The SDK error need not be the outermost
// error: net/http wraps a request's error in a *url.Error, a wrapped
// library such as openai-go may wrap that in turn, and the SDK may add
// context, so that the message can start with that context before the
// category, as in
// "following gateway route to enclave e.example: attestation error: <cause>".
// An SDK error never contains another one.
//
// The caller's own cancellation is in no category. When a call stops because
// the context that the caller passed in, or a request's context, ended, the
// error matches that context's Err() with errors.Is, possibly wrapped, as in
// a *url.Error. A failure that came before the caller cancelled keeps its
// category, and a timeout that the SDK imposes on its own work, such as the
// 30-second limit of an attestation fetch, is an ErrNetwork error. A timeout
// that a wrapped library imposes, such as openai-go's request timeout, ends
// the request's context, and so passes through as that library's error.
//
// An error that a caller's callback returns is classified by the kind of
// callback, as each callback's documentation says, and an SDK error that the
// callback returns can't give the result a second category.
type Error = errs.Error

// The categories of an Error. Check one with errors.Is, for example
// errors.Is(err, tinfoil.ErrAttestation).
var (
	// ErrConfiguration reports invalid caller arguments or client
	// configuration. Retrying won't help.
	ErrConfiguration = errs.ErrConfiguration
	// ErrNetwork reports that the client couldn't reach what it needed: a
	// network failure, a timeout or an HTTP error status while fetching
	// attestation material, a failure of the HTTP stack while it sends a
	// request or reads its response, a request whose body can't be sent again
	// after the enclave's key rotated, or a gateway that keeps routing a
	// request away from its enclave.
	ErrNetwork = errs.ErrNetwork
	// ErrAttestation reports rejected evidence, policy, or channel binding:
	// the enclave couldn't be trusted.
	ErrAttestation = errs.ErrAttestation
)
