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
			expectedTLSPublicKeyFP:       "dd34cd14f50bc0e410886c75bb387a6a4afa3704a03ad22386ec8fb8fe5cef9a",
			expectedHPKEPublicKey:        "0394825e3555b92558d6130d1193bf3049e06a67633ed2a735bb3203cdf6ff1f",
			expectedMeasurementRegisters: []string{"7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114", "67dddcfc052d86247f797ab11f58c6552f8073e8375121b777fb79f4cdddae196381f8b76d40ea1343c99063a9366591", "46658ae5655794d3ea0130e2d425aa002f224c7a47c1eb1792f656d79f808aac6006ce84d71ee24d97c3eea42c867e51", "48c6559c034f1a127bfb9d38576e8efdb53b5237c1440adb926bdbd74d29932a67b6b03c0eb1bc68142d4395c022ce5b", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
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
