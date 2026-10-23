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

func TestParseExpected(t *testing.T) {
	tdx := TDX{MRTD: Register{1}, RTMR0: Register{2}, RTMR1: Register{3}, RTMR2: Register{4}, RTMR3: Register{5}}
	all, err := ParseExpectedTDX(tdx.MRTD.String(), tdx.RTMR0.String(), tdx.RTMR1.String(), tdx.RTMR2.String(), tdx.RTMR3.String())
	require.NoError(t, err)
	assert.Equal(t, tdx.Expected(), all, "arguments are in register order")
	sparse, err := ParseExpectedTDX("", "", "", "", strings.ToUpper(tdx.RTMR3.String()))
	require.NoError(t, err)
	assert.Equal(t, ExpectedTDX{RTMR3: &tdx.RTMR3}, sparse, `"" leaves a register unconstrained`)

	sev := SEVSNP{Launch: Register{1}}
	launch, err := ParseExpectedSEVSNP(sev.Launch.String())
	require.NoError(t, err)
	assert.Equal(t, sev.Expected(), launch)
	unpinned, err := ParseExpectedSEVSNP("")
	require.NoError(t, err)
	assert.Equal(t, ExpectedSEVSNP{}, unpinned)

	_, err = ParseExpectedTDX("", "", "", "abcd", "")
	assert.ErrorContains(t, err, "RTMR2: register must be 96 hex characters")
	_, err = ParseExpectedSEVSNP(strings.Repeat("zz", RegisterSize))
	assert.ErrorContains(t, err, "Launch: register is not hex")
}

func TestExpectedPinsEveryRegister(t *testing.T) {
	tdx := TDX{MRTD: Register{1}, RTMR0: Register{2}, RTMR1: Register{3}, RTMR2: Register{4}, RTMR3: Register{5}}
	assert.Equal(t, ExpectedTDX{MRTD: &tdx.MRTD, RTMR0: &tdx.RTMR0, RTMR1: &tdx.RTMR1, RTMR2: &tdx.RTMR2, RTMR3: &tdx.RTMR3}, tdx.Expected())
	sev := SEVSNP{Launch: Register{1}}
	assert.Equal(t, ExpectedSEVSNP{Launch: &sev.Launch}, sev.Expected())
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
