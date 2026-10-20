package verify

import "fmt"

// Error identifies an error returned by this package: a UsageError or a
// VerificationError.
type Error interface {
	error
	Unwrap() error
	verifyError()
}

// UsageError reports a verifier built or called with invalid inputs. Fix the
// caller; retrying will not help.
type UsageError struct{ Err error }

func (e *UsageError) Error() string { return fmt.Sprintf("usage error: %v", e.Err) }
func (e *UsageError) Unwrap() error { return e.Err }
func (*UsageError) verifyError()    {}

// Layer names the verification layer that rejected a document. More layers
// may be added, so a caller must tolerate values it does not recognize.
type Layer string

const (
	// LayerEnvelope rejects a document that can't be parsed, isn't bound to
	// the caller's nonce, or contradicts itself.
	LayerEnvelope Layer = "envelope"
	// LayerProvenance rejects reference values that fail to authenticate or
	// don't match the requested workload.
	LayerProvenance Layer = "provenance"
	// LayerQuote rejects hardware evidence that isn't authentic.
	LayerQuote Layer = "quote"
	// LayerPolicy rejects authentic evidence that doesn't satisfy the policy.
	LayerPolicy Layer = "policy"
)

// VerificationError reports a document that must not be trusted, and the
// layer that rejected it.
type VerificationError struct {
	Layer Layer
	Err   error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("verification error: %s: %v", e.Layer, e.Err)
}
func (e *VerificationError) Unwrap() error { return e.Err }
func (*VerificationError) verifyError()    {}
