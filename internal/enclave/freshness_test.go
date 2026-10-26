package enclave

import (
	"cmp"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
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

// verifyDocument verifies raw with the verifier a Handle builds from opts.
func verifyDocument(raw, nonce []byte, repo string, opts *Options) (*verify.Verification, error) {
	verifier, err := opts.Verifier()
	if err != nil {
		return nil, err
	}
	return verifier.VerifyV3(raw, nonce, repo)
}

func TestClientFreshnessMaxAge(t *testing.T) {
	defaultMaxAge := defaultFreshnessMaxAge(t)
	defaults, err := NewHandle("enclave.example", "org/repo", nil)
	require.NoError(t, err)
	require.Equal(t, defaultMaxAge, defaults.verifier.FreshnessMaxAge())
	for _, maxAge := range []time.Duration{-time.Nanosecond, -time.Hour} {
		opts := Options{FreshnessMaxAge: maxAge}
		s, err := NewHandle("enclave.example", "org/repo", &opts)
		require.Nil(t, s)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		s, err = NewDefaultHandle(&opts)
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
		opts := Options{FreshnessMaxAge: maxAge, PinnedRegisters: measurement.ExpectedTDX{RTMR3: &measurement.Register{}}}
		s, err := NewDefaultHandle(&opts)
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
	raw, err := fetch.Document(t.Context(), host, "", nonce)
	require.NoError(t, err)
	verified, err := verifyDocument(raw, nonce, repo, nil)
	require.NoError(t, err)
	const maxAge = 30 * 24 * time.Hour
	for _, age := range []time.Duration{0, maxAge} {
		opts := Options{FreshnessMaxAge: age, PinnedRegisters: exactPins(verified.EnclaveMeasurement(), nil)}
		custom, err := verifyDocument(raw, nonce, repo, &opts)
		require.NoError(t, err)
		require.Equal(t, verified.FreshnessExpiresAt().Add(cmp.Or(age, defaultMaxAge)-defaultMaxAge), custom.FreshnessExpiresAt())
	}
	bad := measurement.Register{0xab}
	badPins := exactPins(verified.EnclaveMeasurement(), &bad)
	require.NotEqual(t, exactPins(verified.EnclaveMeasurement(), nil), badPins)
	_, err = verifyDocument(raw, nonce, repo, &Options{PinnedRegisters: badPins})
	var rejected *verify.VerificationError
	require.ErrorAs(t, err, &rejected)
	s, err := NewDefaultHandle(&Options{PinnedRegisters: badPins, FreshnessMaxAge: maxAge})
	require.NoError(t, err)
	_, err = s.Verify()
	var attestation *AttestationError
	require.ErrorAs(t, err, &attestation)
}

// exactPins pins every register of m, replacing its first register with first
// when that is non-nil.
func exactPins(m measurement.Measurement, first *measurement.Register) measurement.Expected {
	switch m := m.(type) {
	case measurement.SEVSNP:
		pins := measurement.ExpectedSEVSNP{Launch: &m.Launch}
		if first != nil {
			pins.Launch = first
		}
		return pins
	case measurement.TDX:
		pins := measurement.ExpectedTDX{MRTD: &m.MRTD, RTMR0: &m.RTMR0, RTMR1: &m.RTMR1, RTMR2: &m.RTMR2, RTMR3: &m.RTMR3}
		if first != nil {
			pins.MRTD = first
		}
		return pins
	default:
		return nil
	}
}
