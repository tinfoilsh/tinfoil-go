package measurement

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttestationFingerprint(t *testing.T) {
	tcs := []struct {
		name        string
		measurement *Measurement
		fingerprint string
	}{
		{
			name: "TDX multi-register",
			measurement: &Measurement{
				Type: TdxGuestV2,
				Registers: []string{
					"7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114",
					"304a1788d349864a75d7e76d54c8d0223207f990e84ad087d28787fff0a7b7cff14c5cb9a96f91ca02e8b32884d9fa81",
					"896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1",
					"fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec",
					"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				},
			},
			fingerprint: "d4c613f1c2919502eee6c8395527086d57e0cf3d7b1c4fda6ba70d421f6a5e08",
		}, {
			name: "single register: raw value returned directly",
			measurement: &Measurement{
				Type:      SevGuestV2,
				Registers: []string{"33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1"},
			},
			fingerprint: "33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.fingerprint, tc.measurement.Fingerprint())
		})
	}
}
