package quote

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

// These tests exercise the final measurement decision, not quote authentication.
// Validate runs this check only after the vendor-policy validation succeeds.
func TestFingerprintDecisionEnforcesFullTDXPin(t *testing.T) {
	pin := &measurement.Measurement{
		Type: measurement.TdxGuestV2,
		Registers: []string{
			strings.Repeat("11", registerSize), strings.Repeat("22", registerSize),
			strings.Repeat("33", registerSize), strings.Repeat("44", registerSize),
			measurement.RTMR3_ZERO,
		},
	}
	expected, err := measurement.Fingerprint(pin, nil, measurement.TdxGuestV2)
	require.NoError(t, err)
	for index, name := range []string{"MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"} {
		t.Run(name, func(t *testing.T) {
			actual := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: append([]string(nil), pin.Registers...)}
			assembled := &AssembledPolicy{expectedFingerprint: expected, quote: newAuthenticated(policy.PlatformTDX, "machine", actual)}
			require.NoError(t, assembled.validateFingerprint())
			actual.Registers[index] = strings.Repeat("ff", registerSize)
			assembled.quote = newAuthenticated(policy.PlatformTDX, "machine", actual)
			require.ErrorContains(t, assembled.validateFingerprint(), "fingerprints do not match")
		})
	}
}

func TestFingerprintDecisionMatchesMultiplatformCode(t *testing.T) {
	code := &measurement.Measurement{
		Type:      measurement.SnpTdxMultiPlatformV1,
		Registers: []string{strings.Repeat("11", registerSize), strings.Repeat("22", registerSize), strings.Repeat("33", registerSize)},
	}
	hw := &measurement.HardwareMeasurement{MRTD: strings.Repeat("44", registerSize), RTMR0: strings.Repeat("55", registerSize)}
	for _, actual := range []*measurement.Measurement{
		{Type: measurement.SevGuestV2, Registers: []string{code.Registers[0]}},
		{Type: measurement.TdxGuestV2, Registers: []string{hw.MRTD, hw.RTMR0, code.Registers[1], code.Registers[2], measurement.RTMR3_ZERO}},
	} {
		t.Run(string(actual.Type), func(t *testing.T) {
			expected, err := measurement.Fingerprint(code, hw, actual.Type)
			require.NoError(t, err)
			assembled := &AssembledPolicy{expectedFingerprint: expected, quote: newAuthenticated("", "machine", actual)}
			require.NoError(t, assembled.validateFingerprint())
		})
	}
}

func TestAuthenticatedObservationsCannotChangeTrustedFacts(t *testing.T) {
	input := &measurement.Measurement{
		Type: measurement.TdxGuestV2,
		Registers: []string{
			strings.Repeat("11", registerSize), strings.Repeat("22", registerSize),
			strings.Repeat("33", registerSize), strings.Repeat("44", registerSize),
			measurement.RTMR3_ZERO,
		},
	}
	expected, err := measurement.Fingerprint(input, nil, input.Type)
	require.NoError(t, err)
	authenticated := newAuthenticated(policy.PlatformTDX, "machine", input)
	assembled := &AssembledPolicy{expectedFingerprint: expected, quote: authenticated}

	input.Registers[0] = strings.Repeat("ff", registerSize)
	authenticated.Measurement.Registers[1] = strings.Repeat("ff", registerSize)
	authenticated.Measurement.Type = measurement.SevGuestV2
	authenticated.Platform = policy.PlatformSEVSNP
	authenticated.Identity = "changed"
	require.Equal(t, policy.PlatformTDX, authenticated.platform)
	require.Equal(t, "machine", authenticated.identity)
	require.NoError(t, assembled.validateFingerprint())

	authenticated.Measurement = nil
	require.NoError(t, assembled.validateFingerprint())
}
