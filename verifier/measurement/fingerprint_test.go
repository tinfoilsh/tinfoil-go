package measurement

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprintCanonicalizesWithoutMutatingInputs(t *testing.T) {
	source := &Measurement{
		Type:      SnpTdxMultiPlatformV1,
		Registers: []string{pinRegister('a'), pinRegister('b'), pinRegister('c')},
	}
	hardware := &HardwareMeasurement{MRTD: pinRegister('d'), RTMR0: pinRegister('e')}
	enclave := &Measurement{
		Type:      TdxGuestV2,
		Registers: []string{hardware.MRTD, hardware.RTMR0, source.Registers[1], source.Registers[2], RTMR3_ZERO},
	}
	want, err := Fingerprint(enclave, nil, TdxGuestV2)
	require.NoError(t, err)
	for i := range source.Registers {
		source.Registers[i] = strings.ToUpper(source.Registers[i])
	}
	hardware.MRTD = strings.ToUpper(hardware.MRTD)
	hardware.RTMR0 = strings.ToUpper(hardware.RTMR0)
	sourceBefore := Measurement{Type: source.Type, Registers: append([]string(nil), source.Registers...)}
	hardwareBefore := *hardware
	got, err := Fingerprint(source, hardware, TdxGuestV2)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, sourceBefore, *source)
	require.Equal(t, hardwareBefore, *hardware)

	for i := range enclave.Registers {
		enclave.Registers[i] = strings.ToUpper(enclave.Registers[i])
	}
	enclaveBefore := Measurement{Type: enclave.Type, Registers: append([]string(nil), enclave.Registers...)}
	got, err = Fingerprint(enclave, nil, TdxGuestV2)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, enclaveBefore, *enclave)

	got, err = Fingerprint(source, nil, SevGuestV2)
	require.NoError(t, err)
	require.Equal(t, pinRegister('a'), got)
	require.Equal(t, sourceBefore, *source)
}

func TestFingerprintCoversEveryTDXRegister(t *testing.T) {
	pin := &Measurement{
		Type:      TdxGuestV2,
		Registers: []string{pinRegister('a'), pinRegister('b'), pinRegister('c'), pinRegister('d'), RTMR3_ZERO},
	}
	want, err := Fingerprint(pin, nil, TdxGuestV2)
	require.NoError(t, err)
	for index, name := range []string{"MRTD", "RTMR0", "RTMR1", "RTMR2", "RTMR3"} {
		t.Run(name, func(t *testing.T) {
			actual := &Measurement{Type: TdxGuestV2, Registers: append([]string(nil), pin.Registers...)}
			actual.Registers[index] = pinRegister('f')
			got, err := Fingerprint(actual, nil, TdxGuestV2)
			require.NoError(t, err)
			require.NotEqual(t, want, got)
		})
	}

	// Platform values expand a multiplatform source; they must never replace
	// registers explicitly supplied by a full TDX pin.
	got, err := Fingerprint(pin, &HardwareMeasurement{MRTD: pinRegister('f'), RTMR0: pinRegister('f')}, TdxGuestV2)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestFingerprintRejectsInvalidRepresentations(t *testing.T) {
	tests := []struct {
		name   string
		m      *Measurement
		hw     *HardwareMeasurement
		target PredicateType
	}{
		{name: "nil", target: SevGuestV2},
		{name: "missing registers", m: &Measurement{Type: TdxGuestV2}, target: TdxGuestV2},
		{name: "extra registers", m: &Measurement{Type: SevGuestV2, Registers: []string{pinRegister('a'), pinRegister('b')}}, target: SevGuestV2},
		{name: "short register", m: &Measurement{Type: SevGuestV2, Registers: []string{"abc"}}, target: SevGuestV2},
		{name: "nonhex register", m: &Measurement{Type: SevGuestV2, Registers: []string{strings.Repeat("z", registerHexLength)}}, target: SevGuestV2},
		{name: "different native target", m: &Measurement{Type: SevGuestV2, Registers: []string{pinRegister('a')}}, target: TdxGuestV2},
		{name: "missing hardware", m: &Measurement{Type: SnpTdxMultiPlatformV1, Registers: []string{pinRegister('a'), pinRegister('b'), pinRegister('c')}}, target: TdxGuestV2},
		{name: "malformed hardware", m: &Measurement{Type: SnpTdxMultiPlatformV1, Registers: []string{pinRegister('a'), pinRegister('b'), pinRegister('c')}}, hw: &HardwareMeasurement{MRTD: "abc", RTMR0: pinRegister('d')}, target: TdxGuestV2},
		{name: "source is not a runtime target", m: &Measurement{Type: SnpTdxMultiPlatformV1, Registers: []string{pinRegister('a'), pinRegister('b'), pinRegister('c')}}, target: SnpTdxMultiPlatformV1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Fingerprint(test.m, test.hw, test.target)
			require.Error(t, err)
		})
	}
}
