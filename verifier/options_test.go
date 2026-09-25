package verifier

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/errs"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

func TestNewDefaults(t *testing.T) {
	v, err := New()
	require.NoError(t, err)
	assert.Equal(t, provenance.MaxFreshnessAge, v.FreshnessMaxAge())
	assert.Nil(t, v.PinnedRegisters())
}

func TestWithFreshnessMaxAge(t *testing.T) {
	// Zero keeps the default, so a caller passing an unset policy field does
	// not silently disable the bound.
	v, err := New(WithFreshnessMaxAge(0))
	require.NoError(t, err)
	assert.Equal(t, provenance.MaxFreshnessAge, v.FreshnessMaxAge())

	v, err = New(WithFreshnessMaxAge(24 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, v.FreshnessMaxAge())

	for _, maxAge := range []time.Duration{-time.Nanosecond, -time.Hour} {
		v, err := New(WithFreshnessMaxAge(maxAge))
		require.Nil(t, v)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		var configuration *errs.ConfigurationError
		require.ErrorAs(t, err, &configuration)
	}
}

func TestWithPinnedRegistersCopies(t *testing.T) {
	register := strings.Repeat("ab", 48)
	pins := &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}
	v, err := New(WithPinnedRegisters(pins))
	require.NoError(t, err)

	// Mutating the caller's measurement after construction must not reach the
	// policy, and the accessor must hand back a copy for the same reason.
	pins.Type = measurement.SevGuestV2
	pins.Registers[4] = "changed"
	assert.Equal(t, measurement.TdxGuestV2, v.PinnedRegisters().Type)
	assert.Equal(t, register, v.PinnedRegisters().Registers[4])

	v.PinnedRegisters().Registers[4] = "changed again"
	assert.Equal(t, register, v.PinnedRegisters().Registers[4])
}

func TestWithPinnedRegistersRejectsInvalid(t *testing.T) {
	for name, pins := range map[string]*measurement.Measurement{
		"unknown type":  {Type: "https://tinfoil.sh/predicate/nope/v1", Registers: []string{""}},
		"wrong count":   {Type: measurement.TdxGuestV2, Registers: []string{""}},
		"not hex":       {Type: measurement.SevGuestV2, Registers: []string{"zz"}},
		"wrong length":  {Type: measurement.SevGuestV2, Registers: []string{"abcd"}},
		"nil registers": {Type: measurement.SevGuestV2},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := New(WithPinnedRegisters(pins))
			require.Nil(t, v)
			var configuration *errs.ConfigurationError
			require.ErrorAs(t, err, &configuration)
		})
	}
}

func TestVerifyV3RejectsBadRepo(t *testing.T) {
	v, err := New()
	require.NoError(t, err)
	verified, err := v.VerifyV3([]byte("{}"), make([]byte, 32), "not a repo reference")
	require.Nil(t, verified)
	var configuration *errs.ConfigurationError
	require.ErrorAs(t, err, &configuration)
}

func TestNewIgnoresNilOption(t *testing.T) {
	v, err := New(nil, WithFreshnessMaxAge(time.Hour), nil)
	require.NoError(t, err)
	assert.Equal(t, time.Hour, v.FreshnessMaxAge())
}

// A caller that ignores New's error holds a nil *Verifier. Verifying with it
// must report a configuration error rather than panicking once a well-formed
// document gets past the parse and the receiver is first dereferenced.
func TestVerifyV3RejectsNilVerifier(t *testing.T) {
	var v *Verifier
	verified, err := v.VerifyV3([]byte("{}"), make([]byte, 32), "org/repo")
	require.Nil(t, verified)
	var configuration *errs.ConfigurationError
	require.ErrorAs(t, err, &configuration)
	require.ErrorContains(t, err, "verifier is required")
}
