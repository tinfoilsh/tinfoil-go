package tinfoil

import "github.com/tinfoilsh/tinfoil-go/internal/errs"

// Error is an SDK error: one of the categories below and the error that
// caused it, in Err. errors.Is reports both the category and the cause, and
// errors.As finds the cause's types; errors.Unwrap can't follow an error with
// two parts, so use those instead. Its message is the category, ": ", then
// the cause, as in "attestation error: <cause>". Upstream API errors, such as
// OpenAI's, keep their own types.
type Error = errs.Error

// The categories of an Error. Check one with errors.Is, for example
// errors.Is(err, tinfoil.ErrAttestation).
var (
	// ErrConfiguration reports invalid caller arguments or client
	// configuration. Retrying won't help.
	ErrConfiguration = errs.ErrConfiguration
	// ErrNetwork reports that the client couldn't reach what it needed: a
	// network failure, a timeout or an HTTP error status while fetching
	// attestation material, or a gateway that keeps routing a request away
	// from its enclave.
	ErrNetwork = errs.ErrNetwork
	// ErrAttestation reports rejected evidence, policy, or channel binding:
	// the enclave couldn't be trusted.
	ErrAttestation = errs.ErrAttestation
)
