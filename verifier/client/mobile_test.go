package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
)

func TestMobileVerificationOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) }))
	defer server.Close()
	originalURL := defaultRouterURL
	defaultRouterURL = server.URL
	t.Cleanup(func() { defaultRouterURL = originalURL })

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
		fallback, err := NewDefaultClient(parsed)
		require.NoError(t, err)
		require.Equal(t, goClient.options, fallback.options)
		require.Equal(t, "inference.tinfoil.sh", fallback.Enclave())
	}
}

func TestMobileVerificationOptionsRejectInvalidPolicy(t *testing.T) {
	for _, raw := range []string{
		``, `null`, `[]`,
		`{"freshness_max_age_ns":-1}`,
		`{"freshness_max_age_ns":9223372036854775808}`,
		`{"freshness_max_age_ns":1.5}`,
		`{"freshness_max_age_ns":"1h"}`,
		`{"freshness_max_age_ns":1,"freshness_max_age_ns":2}`,
		`{"freshness_max_age":1}`,
		`{"pinned_registers":{"register":[]}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			opts, err := ParseVerificationOptionsJSON(raw)
			if err == nil {
				_, err = NewSecureClient("enclave.example", "org/repo", opts)
			}
			require.Error(t, err)
		})
	}
}
