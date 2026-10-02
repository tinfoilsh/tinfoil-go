package client

import (
	"cmp"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// defaultFreshnessMaxAge is the bound a client inherits from the verifier when
// its options leave FreshnessMaxAge zero.
func defaultFreshnessMaxAge(t *testing.T) time.Duration {
	t.Helper()
	verifier, err := verify.NewVerifier()
	require.NoError(t, err)
	return verifier.FreshnessMaxAge()
}

// verifyDocument verifies raw with the verifier a SecureClient builds from opts.
func verifyDocument(raw, nonce []byte, repo string, opts *VerificationOptions) (*verify.Verification, error) {
	verifier, err := opts.verifier()
	if err != nil {
		return nil, err
	}
	return verifier.VerifyV3(raw, nonce, repo)
}

func TestClientFreshnessMaxAge(t *testing.T) {
	defaultMaxAge := defaultFreshnessMaxAge(t)
	defaults, err := NewSecureClient("enclave.example", "org/repo", nil)
	require.NoError(t, err)
	require.Equal(t, defaultMaxAge, defaults.verifier.FreshnessMaxAge())
	for _, maxAge := range []time.Duration{-time.Nanosecond, -time.Hour} {
		opts := VerificationOptions{FreshnessMaxAge: maxAge}
		s, err := NewSecureClient("enclave.example", "org/repo", &opts)
		require.Nil(t, s)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		s, err = NewDefaultClient(&opts)
		require.Nil(t, s)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		_, err = verifyDocument(nil, nil, "org/repo", &opts)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) }))
	defer server.Close()
	originalURL := defaultRouterURL
	defaultRouterURL = server.URL
	t.Cleanup(func() { defaultRouterURL = originalURL })
	for _, maxAge := range []time.Duration{0, 24 * time.Hour, 30 * 24 * time.Hour} {
		opts := VerificationOptions{FreshnessMaxAge: maxAge, PinnedRegisters: &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: measurement.RTMR3_ZERO}}}
		s, err := NewDefaultClient(&opts)
		require.NoError(t, err)
		require.Equal(t, "inference.tinfoil.sh", s.Enclave())
		require.Equal(t, cmp.Or(maxAge, defaultMaxAge), s.verifier.FreshnessMaxAge())
		require.Equal(t, opts.PinnedRegisters, s.verifier.PinnedRegisters())
	}
}

func TestLiveVerifyFreshnessExpiration(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	defaultMaxAge := defaultFreshnessMaxAge(t)
	host, repo := os.Getenv(enclaveEnvVar), os.Getenv(repoEnvVar)
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	raw, err := fetch.Document(host, "", nonce)
	require.NoError(t, err)
	verified, err := verifyDocument(raw, nonce, repo, nil)
	require.NoError(t, err)
	const maxAge = 30 * 24 * time.Hour
	for _, age := range []time.Duration{0, maxAge} {
		opts := VerificationOptions{FreshnessMaxAge: age, PinnedRegisters: verified.EnclaveMeasurement}
		custom, err := verifyDocument(raw, nonce, repo, &opts)
		require.NoError(t, err)
		require.Equal(t, verified.FreshnessExpiresAt.Add(cmp.Or(age, defaultMaxAge)-defaultMaxAge), custom.FreshnessExpiresAt)
	}
	badPins := cloneMeasurement(verified.EnclaveMeasurement)
	badPins.Registers[0] = strings.Repeat("ab", 48)
	require.NotEqual(t, verified.EnclaveMeasurement.Registers[0], badPins.Registers[0])
	_, err = verifyDocument(raw, nonce, repo, &VerificationOptions{PinnedRegisters: badPins})
	var attestation *AttestationError
	require.ErrorAs(t, err, &attestation)
	s, err := NewDefaultClient(&VerificationOptions{PinnedRegisters: badPins, FreshnessMaxAge: maxAge})
	require.NoError(t, err)
	_, err = s.Verify()
	require.ErrorAs(t, err, &attestation)
}
