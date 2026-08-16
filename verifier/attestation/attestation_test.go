package attestation

import (
	"encoding/json"
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

func TestGuestVerify(t *testing.T) {
	tcs := []struct {
		attestation                  string
		expectedErr                  error
		expectedFormat               PredicateType
		expectedTLSPublicKeyFP       string
		expectedHPKEPublicKey        string
		expectedMeasurementRegisters []string
	}{
		{
			attestation:                  `{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v2","body":"H4sIAAAAAAAA/2JmgAEEixBgZGBg4AKzxEPU0eQETrU6V/UVB3t6X/nzPHnDqkuB7Ge7tj5ZEHio29Wfkc1uX9Sclq9brfxurj5f8/1vsLnEKWGd+VvbrZlW1uopNP7g1X277qF1y53Evj/F31o35j7JULPg0r0S+zF28d3utXtmKJ26X/2ndOpEHVfxXfmrpYMOEO1oGgGNBec2/VR6lX2Gl0OiQHRZX6rfLIn+iuYbKf+jFB4bqZ34TwDAwlFSkBGr+VIfV+XIhzFXsbbMitzRGPOTM8J+9sr3+qxGEkfMP1svbH7yRHSD5eb6JlZVrovx3R0LFq+9+eVA44HyWR5vlUTM+1xg5muYMzKAMIxPxyCiCHQ6e7XWK8xY82mR/JozTx04Vy5l8FSb5PHojvm2wD2bL32f4PhFweCczqKfEgb9gr/XG+Iy57HDxR1FBzhUzT5FZUW/TOHzX/fB7uei0kcHzO5v62TjbzG4Zxh1YsrdgwmpTrsN8vatoq8vRwEuAAgAAP//tiY3daAEAAA="}`,
			expectedErr:                  nil,
			expectedFormat:               SevGuestV2,
			expectedTLSPublicKeyFP:       "10ca85437a8e7353494bd4fce763b0aad25107cd8ab5e4a051c28b454f01063e",
			expectedHPKEPublicKey:        "be5a9c84f5b53a4ed9abcf7cf7fd533718ca132c9fb5873b02a97d2e2081f80d",
			expectedMeasurementRegisters: []string{"2dedaee13b84dc618efc73f685b16de46826380a2dd45df15da3dd8badbc9822cadf7bfc7595912c4517ba6fab1b52c0"},
		},
		{
			attestation:                  `{"format":"https://tinfoil.sh/predicate/tdx-guest/v2","body":"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"}`,
			expectedErr:                  nil,
			expectedFormat:               TdxGuestV2,
			expectedTLSPublicKeyFP:       "97e891b5b4b34467e824b5314e3b2f4266a500c85885936a5f69a31744c16b93",
			expectedHPKEPublicKey:        "e0f6b9293608bee47400df5b994d16ea6c981ba06c5f438121b47381edefc210",
			expectedMeasurementRegisters: []string{"7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114", "a2749c840579faca6adf0c9c3ab69f277556cda67f8a6b3553c2c7fbf00e9706ec77a6f6960d802433b339ff8b72eefb", "46658ae5655794d3ea0130e2d425aa002f224c7a47c1eb1792f656d79f808aac6006ce84d71ee24d97c3eea42c867e51", "9682bebdd95156de5bc378d9147ab7232bef0b60b21b7722883e86078723b011e9d1c64156a34e050e5d19ee9ade83ac", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	for _, tc := range tcs {
		t.Run("", func(t *testing.T) {
			verification, err := VerifyAttestationJSON([]byte(tc.attestation))
			require.NoError(t, err)
			assert.Equal(t, tc.expectedFormat, verification.Measurement.Type)
			assert.Equal(t, tc.expectedErr, err)
			assert.Equal(t, tc.expectedTLSPublicKeyFP, verification.TLSPublicKeyFP)
			assert.Equal(t, tc.expectedHPKEPublicKey, verification.HPKEPublicKey)
			assert.Equal(t, tc.expectedMeasurementRegisters, verification.Measurement.Registers)
		})
	}
}

func TestFetchBundle(t *testing.T) {
	bundle, err := FetchBundle()
	require.NoError(t, err)
	require.NotNil(t, bundle)

	assert.NotEmpty(t, bundle.Domain)
	assert.NotEmpty(t, bundle.Digest)
	assert.NotNil(t, bundle.EnclaveAttestationReport)
	assert.NotEmpty(t, bundle.EnclaveAttestationReport.Format)
	assert.NotEmpty(t, bundle.EnclaveAttestationReport.Body)
	assert.NotEmpty(t, bundle.VCEK)
	assert.NotEmpty(t, bundle.SigstoreBundle)
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

func TestFetchBundleFromRejectsNonHTTPS(t *testing.T) {
	_, err := FetchBundleFrom("http://atc.example")
	require.Error(t, err)
	require.Contains(t, err.Error(), "https")
}

func TestFetchBundleForRejectsNonHTTPS(t *testing.T) {
	_, err := FetchBundleFor("http://atc.example", "https://enclave.test", "org/repo")
	require.Error(t, err)
	require.Contains(t, err.Error(), "https")
}

func TestBundleRequestJSON(t *testing.T) {
	b, err := json.Marshal(bundleRequest{EnclaveURL: "https://e.test", Repo: "org/repo"})
	require.NoError(t, err)
	require.JSONEq(t, `{"enclaveUrl":"https://e.test","repo":"org/repo"}`, string(b))

	// Empty fields are omitted so the service falls back to its defaults.
	b, err = json.Marshal(bundleRequest{EnclaveURL: "https://e.test"})
	require.NoError(t, err)
	require.JSONEq(t, `{"enclaveUrl":"https://e.test"}`, string(b))
}
