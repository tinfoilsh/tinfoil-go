package verify

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireRejectedAt asserts that err is a VerificationError from layer.
func requireRejectedAt(t *testing.T, err error, layer Layer, msgAndArgs ...any) {
	t.Helper()
	var rejected *VerificationError
	require.ErrorAs(t, err, &rejected, msgAndArgs...)
	require.Equal(t, layer, rejected.Layer, msgAndArgs...)
}

func TestVerificationErrorNamesItsLayer(t *testing.T) {
	err := &VerificationError{Layer: LayerQuote, Err: errors.New("report signature is invalid")}
	require.EqualError(t, err, "verification error: quote: report signature is invalid")
}
