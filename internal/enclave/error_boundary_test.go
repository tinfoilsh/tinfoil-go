package enclave

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// The outermost verify error decides the SDK category, so a UsageError
// wrapped inside a VerificationError is still an attestation failure.
func TestFromVerifyClassifiesByOutermostVerifyError(t *testing.T) {
	usage := &verify.UsageError{Err: errors.New("bad input")}
	require.ErrorIs(t, fromVerify(usage), errs.ErrConfiguration)
	rejected := &verify.VerificationError{Err: usage}
	require.ErrorIs(t, fromVerify(rejected), errs.ErrAttestation)
	require.NotErrorIs(t, fromVerify(rejected), errs.ErrConfiguration)
	require.ErrorIs(t, fromVerify(rejected), rejected)
	require.NoError(t, fromVerify(nil))
}
