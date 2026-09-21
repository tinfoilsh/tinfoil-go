package measurement

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateCodeCopiesAndNormalizes(t *testing.T) {
	register := strings.Repeat("ab", codeRegisterBytes)
	input := &CodeMeasurement{SNPMeasurement: strings.ToUpper(register), TDXMeasurement: &TDXMeasurement{
		RTMR1: strings.ToUpper(register), RTMR2: register,
	}}
	got, err := ValidateCode(input)
	require.NoError(t, err)
	require.Equal(t, &CodeMeasurement{SNPMeasurement: register, TDXMeasurement: &TDXMeasurement{RTMR1: register, RTMR2: register}}, got)
	input.SNPMeasurement = "changed"
	input.TDXMeasurement.RTMR1 = "changed"
	require.Equal(t, register, got.SNPMeasurement)
	require.Equal(t, register, got.TDXMeasurement.RTMR1)
	for _, pin := range []*CodeMeasurement{
		{SNPMeasurement: register},
		{TDXMeasurement: &TDXMeasurement{RTMR1: register, RTMR2: register}},
	} {
		got, err := ValidateCode(pin)
		require.NoError(t, err)
		require.Equal(t, pin, got)
	}
}

func TestValidateCodeRejectsMalformedPins(t *testing.T) {
	register := strings.Repeat("ab", codeRegisterBytes)
	for name, pin := range map[string]*CodeMeasurement{
		"nil":                       nil,
		"empty":                     {},
		"short SNP":                 {SNPMeasurement: register[1:]},
		"long SNP":                  {SNPMeasurement: register + "a"},
		"non-hex SNP":               {SNPMeasurement: "g" + register[1:]},
		"empty TDX":                 {TDXMeasurement: &TDXMeasurement{}},
		"missing RTMR1":             {TDXMeasurement: &TDXMeasurement{RTMR2: register}},
		"missing RTMR2":             {TDXMeasurement: &TDXMeasurement{RTMR1: register}},
		"short RTMR1":               {TDXMeasurement: &TDXMeasurement{RTMR1: "abc", RTMR2: register}},
		"non-hex RTMR2":             {TDXMeasurement: &TDXMeasurement{RTMR1: register, RTMR2: "g" + register[1:]}},
		"partial TDX alongside SNP": {SNPMeasurement: register, TDXMeasurement: &TDXMeasurement{RTMR1: register}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ValidateCode(pin)
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
}
