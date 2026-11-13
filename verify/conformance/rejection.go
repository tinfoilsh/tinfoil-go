//go:build tinfoil_conformance

package conformance

import (
	"errors"

	"github.com/tinfoilsh/tinfoil-go/verify"
)

// RejectionCode reports a VerifyV3 error the way the wire contract does: a
// VerificationError is rejected with its layer's code, and a UsageError means
// the input was malformed. Anything else, including a VerificationError
// without a known layer, is a bug in the verifier and reports ExitInternal.
func RejectionCode(err error) (code string, exit int) {
	var classified verify.Error
	if !errors.As(err, &classified) {
		return "", ExitInternal
	}
	switch classified := classified.(type) {
	case *verify.UsageError:
		return "MALFORMED_INPUT", ExitMalformed
	case *verify.VerificationError:
		switch classified.Layer {
		case verify.LayerEnvelope:
			return "ENVELOPE_REJECTED", ExitRejected
		case verify.LayerProvenance:
			return "PROVENANCE_REJECTED", ExitRejected
		case verify.LayerQuote:
			return "QUOTE_REJECTED", ExitRejected
		case verify.LayerPolicy:
			return "POLICY_REJECTED", ExitRejected
		}
	}
	return "", ExitInternal
}
