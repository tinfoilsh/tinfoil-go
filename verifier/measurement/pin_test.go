package measurement

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pinRegister(digit byte) string {
	return strings.Repeat(string(digit), registerHexLength)
}

func TestValidatePinNormalizesAndCopies(t *testing.T) {
	input := &Measurement{
		Type:      TdxGuestV2,
		Registers: []string{strings.ToUpper(pinRegister('a')), pinRegister('b'), pinRegister('c'), pinRegister('d'), RTMR3_ZERO},
	}

	validated, err := ValidatePin(input)
	require.NoError(t, err)
	assert.Equal(t, pinRegister('a'), validated.Registers[0])

	input.Registers[1] = pinRegister('f')
	input.Type = SevGuestV2
	assert.Equal(t, TdxGuestV2, validated.Type)
	assert.Equal(t, pinRegister('b'), validated.Registers[1], "validated copy must not share the caller's slice")
}

func TestValidatePinRejects(t *testing.T) {
	valid := pinRegister('a')
	tests := []struct {
		name    string
		m       *Measurement
		wantErr error
	}{
		{"nil", nil, ErrPinnedMeasurementNil},
		{"empty type", &Measurement{Registers: []string{valid}}, ErrPinnedMeasurementType},
		{"unknown type", &Measurement{Type: "https://example.com/unknown", Registers: []string{valid}}, ErrPinnedMeasurementType},
		{"sev too many", &Measurement{Type: SevGuestV2, Registers: []string{valid, valid}}, ErrPinnedRegisterCount},
		{"sev none", &Measurement{Type: SevGuestV2}, ErrPinnedRegisterCount},
		{"tdx too few", &Measurement{Type: TdxGuestV2, Registers: []string{valid, valid, valid, valid}}, ErrPinnedRegisterCount},
		{"mp too many", &Measurement{Type: SnpTdxMultiPlatformV1, Registers: []string{valid, valid, valid, valid}}, ErrPinnedRegisterCount},
		{"short", &Measurement{Type: SevGuestV2, Registers: []string{"abc"}}, ErrPinnedRegisterEncoding},
		{"non-hex", &Measurement{Type: SevGuestV2, Registers: []string{strings.Repeat("g", registerHexLength)}}, ErrPinnedRegisterEncoding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePin(tt.m)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
