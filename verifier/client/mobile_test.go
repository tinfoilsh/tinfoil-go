package client

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
)

func TestMobileVerificationOptions(t *testing.T) {
	register := strings.Repeat("ab", 48)
	for _, tt := range []struct {
		raw  string
		opts VerificationOptions
	}{
		{`{}`, VerificationOptions{}},
		{
			`{"freshness_max_age_ns":3600000000000,"pinned_registers":{"type":"https://tinfoil.sh/predicate/tdx-guest/v2","registers":["","","","","` + register + `"]}}`,
			VerificationOptions{FreshnessMaxAge: time.Hour, PinnedRegisters: &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: register}}},
		},
	} {
		goClient, err := NewSecureClient("enclave.example", "org/repo", &tt.opts)
		require.NoError(t, err)
		parsed, err := ParseVerificationOptionsJSON(tt.raw)
		require.NoError(t, err)
		mobileClient, err := NewSecureClient("enclave.example", "org/repo", parsed)
		require.NoError(t, err)
		require.Equal(t, goClient.options, mobileClient.options)
	}
}

func TestMobileVerificationOptionsRejectInvalidPolicy(t *testing.T) {
	for _, raw := range []string{`null`, `{"freshness_max_age_ns":-1}`, `{"freshness_max_age":1}`} {
		t.Run(raw, func(t *testing.T) {
			opts, err := ParseVerificationOptionsJSON(raw)
			if err == nil {
				_, err = NewSecureClient("enclave.example", "org/repo", opts)
			}
			require.Error(t, err)
		})
	}
}

func TestMobileWorkloadPinOptions(t *testing.T) {
	register := strings.Repeat("ab", workloadRegisterBytes)
	for _, tt := range []struct {
		raw  string
		opts VerificationOptions
	}{
		{
			`{"pinned_code":{"snp_measurement":"` + strings.ToUpper(register) + `"}}`,
			VerificationOptions{PinnedCode: &measurement.CodeMeasurement{SNPMeasurement: register}},
		},
		{
			`{"pinned_code":{"tdx_measurement":{"rtmr1":"` + register + `","rtmr2":"` + register + `"}},"pinned_shape":{"cpus":4,"memory_mb":8192,"disks":1},"freshness_max_age_ns":3600000000000}`,
			VerificationOptions{PinnedCode: &measurement.CodeMeasurement{TDXMeasurement: &measurement.TDXMeasurement{RTMR1: register, RTMR2: register}}, PinnedShape: &policy.Shape{CPUs: 4, MemoryMB: 8192, Disks: 1}, FreshnessMaxAge: time.Hour},
		},
	} {
		parsed, err := ParseVerificationOptionsJSON(tt.raw)
		require.NoError(t, err)
		mobileClient, err := NewSecureClient("enclave.example", "", parsed)
		require.NoError(t, err)
		goClient, err := NewSecureClient("enclave.example", "", &tt.opts)
		require.NoError(t, err)
		require.Equal(t, goClient.options, mobileClient.options)
	}
}

func TestMobileWorkloadPinRejectsInvalidOptions(t *testing.T) {
	for _, raw := range []string{
		`{"pinned_code":{}}`,
		`{"pinned_code":{"snp_measurement":"abc"}}`,
		`{"pinned_code":{"tdx_measurement":{"rtmr1":"abc"}}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			opts, err := ParseVerificationOptionsJSON(raw)
			require.NoError(t, err)
			c, err := NewSecureClient("enclave.example", "", opts)
			require.ErrorContains(t, err, "invalid pinned code")
			require.Nil(t, c)
		})
	}
}

func TestMobileWorkloadPinRejectsInvalidJSON(t *testing.T) {
	register := strings.Repeat("ab", workloadRegisterBytes)
	validCode := `"pinned_code":{"tdx_measurement":{"rtmr1":"` + register + `","rtmr2":"` + register + `"}}`
	for _, raw := range []string{
		`{"pinned_code":"not a measurement"}`,
		`{"pinned_code":{"tdx_measurement":{"mrtd":"abc"}}}`,
		`{` + validCode + `,"pinned_shape":{"memoryMB":8192}}`,
		`{` + validCode + `,"pinned_shape":{"cpus":4,"cpus":8}}`,
		`{` + validCode + `,"pinned_shape":[]}`,
		`{"pinned_code":{}}{}`,
	} {
		t.Run(raw, func(t *testing.T) {
			opts, err := ParseVerificationOptionsJSON(raw)
			require.ErrorContains(t, err, "parsing verification options")
			require.Nil(t, opts)
		})
	}
}
