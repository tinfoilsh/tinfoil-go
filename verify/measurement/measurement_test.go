package measurement

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRegister(t *testing.T) {
	want := Register{0xab, 0xcd}
	lower := "abcd" + strings.Repeat("00", RegisterSize-2)
	for _, input := range []string{lower, strings.ToUpper(lower)} {
		got, err := ParseRegister(input)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}
	assert.Equal(t, lower, want.String(), "the text form is lowercase")

	// The length is checked before decoding, so an oversized input is rejected
	// without being decoded.
	for name, tc := range map[string]struct{ input, err string }{
		"not hex":          {strings.Repeat("zz", RegisterSize), "not hex"},
		"too short":        {strings.Repeat("ab", RegisterSize-1), "96 hex characters"},
		"too long":         {strings.Repeat("ab", RegisterSize+1), "96 hex characters"},
		"too long, no hex": {strings.Repeat("zz", RegisterSize+1), "96 hex characters"},
		"empty":            {"", "96 hex characters"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRegister(tc.input)
			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestRegisterTextRoundTrip(t *testing.T) {
	register := Register{0x01}
	encoded, err := json.Marshal(ExpectedTDX{RTMR3: &register})
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"RTMR3":"01`)
	assert.Contains(t, string(encoded), `"MRTD":null`)

	var decoded ExpectedTDX
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.NotNil(t, decoded.RTMR3)
	assert.Equal(t, register, *decoded.RTMR3)
	assert.Nil(t, decoded.MRTD)

	assert.Error(t, json.Unmarshal([]byte(`{"RTMR3":"zz"}`), &decoded))
}

func TestString(t *testing.T) {
	register := Register{0xab}
	assert.Equal(t, "SEV-SNP\nLaunch "+register.String(), SEVSNP{Launch: register}.String())
	assert.Equal(t, "TDX\nMRTD   any\nRTMR0  any\nRTMR1  "+register.String()+"\nRTMR2  any\nRTMR3  any",
		ExpectedTDX{RTMR1: &register}.String())
}

func TestCloneSharesNoRegisters(t *testing.T) {
	register := Register{0xab}
	for _, original := range []Expected{
		ExpectedSEVSNP{Launch: &register},
		ExpectedTDX{RTMR1: &register},
	} {
		clone := original.Clone()
		assert.Equal(t, original, clone)
		register[0] = 0xcd
		assert.NotEqual(t, original, clone, "changing the original's register must not reach the clone")
		register[0] = 0xab
	}
	assert.Equal(t, ExpectedTDX{}, ExpectedTDX{}.Clone(), "unconstrained registers stay nil")
}
