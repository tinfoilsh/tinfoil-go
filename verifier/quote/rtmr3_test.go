package quote

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

func TestRTMR3ComesFromCallerForEachCodeFormat(t *testing.T) {
	register := strings.Repeat("ab", 48)
	sealed := strings.Repeat("cd", 48)
	for _, m := range []*measurement.Measurement{
		{Type: measurement.SnpTdxMultiPlatformV1, Registers: []string{register, register, register}},
		{Type: measurement.TdxGuestV2, Registers: []string{register, register, register, register, register}},
	} {
		t.Run(string(m.Type), func(t *testing.T) {
			defaults, err := tdxCodeRegisters(m)
			require.NoError(t, err)
			require.Equal(t, make([]byte, 48), defaults.RTMR3)
			want, err := (Options{ExpectedRTMR3: sealed}).rtmr3()
			require.NoError(t, err)
			got, err := tdxCodeRegistersWithRTMR3(m, want)
			require.NoError(t, err)
			require.Equal(t, sealed, hex.EncodeToString(got.RTMR3))
			require.Equal(t, register, hex.EncodeToString(got.RTMR1))
			require.Equal(t, register, hex.EncodeToString(got.RTMR2))
			require.Equal(t, register, m.Registers[len(m.Registers)-1], "do not rewrite signed code measurements")
		})
	}
}

func TestSEVRejectsRuntimeRTMR3Expectation(t *testing.T) {
	for _, kind := range []measurement.PredicateType{measurement.SevGuestV2, measurement.SnpTdxMultiPlatformV1} {
		_, err := AssembleWithOptions(nil, &measurement.Measurement{Type: kind}, testShape, [64]byte{}, &Authenticated{Platform: policy.PlatformSEVSNP}, Options{ExpectedRTMR3: strings.Repeat("ab", 48)})
		require.ErrorContains(t, err, "SEV-SNP has no RTMR3")
	}
}

func TestRTMR3OptionsRejectMalformedRegister(t *testing.T) {
	for _, value := range []string{"ab", strings.Repeat("a", 95), strings.Repeat("00", 49), strings.Repeat("xz", 48)} {
		require.Error(t, (Options{ExpectedRTMR3: value}).Validate())
	}
	require.NoError(t, (Options{}).Validate())
	require.NoError(t, (Options{ExpectedRTMR3: strings.Repeat("AB", 48)}).Validate())
}
