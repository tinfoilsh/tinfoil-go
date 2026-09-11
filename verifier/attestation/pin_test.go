package attestation

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pinRegister(digit byte) string {
	return strings.Repeat(string(digit), registerHexLength)
}

func TestValidatePinnedMeasurementNormalizesAndCopies(t *testing.T) {
	input := &Measurement{
		Type:      TdxGuestV2,
		Registers: []string{strings.ToUpper(pinRegister('a')), pinRegister('b'), pinRegister('c'), pinRegister('d'), RTMR3_ZERO},
	}

	validated, err := ValidatePinnedMeasurement(input)
	require.NoError(t, err)
	assert.Equal(t, pinRegister('a'), validated.Registers[0])

	input.Registers[1] = pinRegister('f')
	assert.Equal(t, pinRegister('b'), validated.Registers[1], "validated copy must not share the caller's slice")
}

func TestValidatePinnedMeasurementRejects(t *testing.T) {
	valid := pinRegister('a')
	tests := []struct {
		name    string
		m       *Measurement
		wantErr error
	}{
		{"nil", nil, ErrPinnedMeasurementNil},
		{"unsupported type", &Measurement{Type: HardwareMeasurementsV1, Registers: []string{valid}}, ErrPinnedMeasurementType},
		{"sev too many", &Measurement{Type: SevGuestV2, Registers: []string{valid, valid}}, ErrPinnedRegisterCount},
		{"tdx too few", &Measurement{Type: TdxGuestV2, Registers: []string{valid, valid, valid, valid}}, ErrPinnedRegisterCount},
		{"mp too many", &Measurement{Type: SnpTdxMultiPlatformV1, Registers: []string{valid, valid, valid, valid}}, ErrPinnedRegisterCount},
		{"short", &Measurement{Type: SevGuestV2, Registers: []string{"abc"}}, ErrPinnedRegisterEncoding},
		{"non-hex", &Measurement{Type: SevGuestV2, Registers: []string{strings.Repeat("g", registerHexLength)}}, ErrPinnedRegisterEncoding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePinnedMeasurement(tt.m)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestValidateHardwareMeasurements(t *testing.T) {
	validated, err := ValidateHardwareMeasurements(nil)
	require.NoError(t, err)
	assert.Nil(t, validated)

	validated, err = ValidateHardwareMeasurements([]*HardwareMeasurement{})
	require.NoError(t, err)
	assert.Nil(t, validated)

	entry := &HardwareMeasurement{ID: "platform@digest", MRTD: strings.ToUpper(pinRegister('a')), RTMR0: pinRegister('b')}
	validated, err = ValidateHardwareMeasurements([]*HardwareMeasurement{entry})
	require.NoError(t, err)
	assert.Equal(t, pinRegister('a'), validated[0].MRTD)
	entry.RTMR0 = pinRegister('f')
	assert.Equal(t, pinRegister('b'), validated[0].RTMR0, "validated copy must not alias the caller's entry")

	for name, hw := range map[string][]*HardwareMeasurement{
		"nil entry":  {nil},
		"missing ID": {{MRTD: pinRegister('a'), RTMR0: pinRegister('b')}},
		"short MRTD": {{ID: "p", MRTD: "abc", RTMR0: pinRegister('b')}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateHardwareMeasurements(hw)
			assert.Error(t, err)
		})
	}
}
