package measurement

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMeasurementEquals(t *testing.T) {
	tests := []struct {
		name    string
		m1      *Measurement
		m2      *Measurement
		wantErr error
	}{

		{
			name:    "multi-platform to multi-platform equal",
			wantErr: nil,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
		}, {
			name:    "multi-platform to multi-platform mismatch",
			wantErr: ErrMultiPlatformMismatch,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp_other", "rtmr1", "rtmr2"},
			},
		}, {
			name:    "multi-platform SEV-SNP v2 match",
			wantErr: nil,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SevGuestV2,
				Registers: []string{"sevsnp"},
			},
		}, {
			name:    "multi-platform TDX v2 match",
			wantErr: nil,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      TdxGuestV2,
				Registers: []string{"mrtd", "rtmr0", "rtmr1", "rtmr2", RTMR3_ZERO},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.m1.Equals(tt.m2), tt.wantErr)
		})
	}
}

func TestAttestationFingerprint(t *testing.T) {
	routerMpMeasurement := &Measurement{
		Type: SnpTdxMultiPlatformV1,
		Registers: []string{
			"33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1",
			"896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1",
			"fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec",
		},
	}

	tcs := []struct {
		name                       string
		sourceMeasurement          *Measurement
		enclaveMeasurement         *Measurement
		hwMeasurement              *HardwareMeasurement
		expectedSourceFingerprint  string
		expectedEnclaveFingerprint string
	}{
		{
			name:              "TDX multi-register: type URL included in hash, source != enclave",
			sourceMeasurement: routerMpMeasurement,
			enclaveMeasurement: &Measurement{
				Type: TdxGuestV2,
				Registers: []string{
					"7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114",
					"304a1788d349864a75d7e76d54c8d0223207f990e84ad087d28787fff0a7b7cff14c5cb9a96f91ca02e8b32884d9fa81",
					"896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1",
					"fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec",
					"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				},
			},
			hwMeasurement: &HardwareMeasurement{
				MRTD:  "7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114",
				RTMR0: "304a1788d349864a75d7e76d54c8d0223207f990e84ad087d28787fff0a7b7cff14c5cb9a96f91ca02e8b32884d9fa81",
			},
			expectedSourceFingerprint:  "02e628595f1bbd914799fdf0eab30ab954b0dda6ca96fcdbcbc3ff71cad44e40",
			expectedEnclaveFingerprint: "d4c613f1c2919502eee6c8395527086d57e0cf3d7b1c4fda6ba70d421f6a5e08",
		}, {
			name:              "SEV single-register: raw value returned directly, source == enclave",
			sourceMeasurement: routerMpMeasurement,
			enclaveMeasurement: &Measurement{
				Type:      SevGuestV2,
				Registers: []string{"33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1"},
			},
			hwMeasurement:              nil,
			expectedSourceFingerprint:  "33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1",
			expectedEnclaveFingerprint: "33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			enclaveFP, err := Fingerprint(tc.enclaveMeasurement, tc.hwMeasurement, tc.enclaveMeasurement.Type)
			require.NoError(t, err)

			sourceFP, err := Fingerprint(tc.sourceMeasurement, tc.hwMeasurement, tc.enclaveMeasurement.Type)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedSourceFingerprint, sourceFP)
			assert.Equal(t, tc.expectedEnclaveFingerprint, enclaveFP)
		})
	}
}
