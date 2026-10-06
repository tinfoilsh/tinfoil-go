package enclave

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestMobileOptions(t *testing.T) {
	register := strings.Repeat("ab", 48)
	for _, tt := range []struct {
		raw  string
		opts Options
	}{
		{`{}`, Options{}},
		{
			`{"freshness_max_age_ns":3600000000000,"pinned_registers":{"type":"https://tinfoil.sh/predicate/tdx-guest/v2","registers":["","","","","` + register + `"]}}`,
			Options{FreshnessMaxAge: time.Hour, PinnedRegisters: &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}},
		},
	} {
		goClient, err := NewHandle("enclave.example", "org/repo", &tt.opts)
		require.NoError(t, err)
		parsed, err := ParseOptionsJSON(tt.raw)
		require.NoError(t, err)
		mobileClient, err := NewHandle("enclave.example", "org/repo", parsed)
		require.NoError(t, err)
		require.Equal(t, goClient.verifier.FreshnessMaxAge(), mobileClient.verifier.FreshnessMaxAge())
		require.Equal(t, goClient.verifier.PinnedRegisters(), mobileClient.verifier.PinnedRegisters())
	}
}

func TestMobileOptionsRejectInvalidPolicy(t *testing.T) {
	for _, raw := range []string{`null`, `{"freshness_max_age_ns":-1}`, `{"freshness_max_age":1}`} {
		t.Run(raw, func(t *testing.T) {
			opts, err := ParseOptionsJSON(raw)
			if err == nil {
				_, err = NewHandle("enclave.example", "org/repo", opts)
			}
			require.Error(t, err)
		})
	}
}
