//go:build tinfoil_conformance

package conformance

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestRejectionCodeReadsTheLayer(t *testing.T) {
	cause := errors.New("cause")
	for _, tc := range []struct {
		err  error
		code string
		exit int
	}{
		{&verify.VerificationError{Layer: verify.LayerEnvelope, Err: cause}, "ENVELOPE_REJECTED", ExitRejected},
		{&verify.VerificationError{Layer: verify.LayerProvenance, Err: cause}, "PROVENANCE_REJECTED", ExitRejected},
		{&verify.VerificationError{Layer: verify.LayerQuote, Err: cause}, "QUOTE_REJECTED", ExitRejected},
		{fmt.Errorf("context: %w", &verify.VerificationError{Layer: verify.LayerPolicy, Err: cause}), "POLICY_REJECTED", ExitRejected},
		{&verify.UsageError{Err: cause}, "MALFORMED_INPUT", ExitMalformed},
		// A rejection without a layer, or without a verify type, is a
		// verifier bug and must not pass for a verdict.
		{&verify.VerificationError{Err: cause}, "", ExitInternal},
		{cause, "", ExitInternal},
	} {
		code, exit := RejectionCode(tc.err)
		require.Equal(t, tc.code, code, tc.err)
		require.Equal(t, tc.exit, exit, tc.err)
	}
}
