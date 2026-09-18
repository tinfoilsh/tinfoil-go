package tinfoil

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClientRejectsInvalidFreshnessOverride(t *testing.T) {
	for _, age := range []time.Duration{0, -time.Hour} {
		_, err := NewClientWithOptions(WithEnclave("invalid.invalid"), WithFreshnessMaxAge(age))
		require.ErrorContains(t, err, "freshness maximum age must be positive")
	}
}
