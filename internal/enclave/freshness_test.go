package enclave

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// verifyDocument verifies raw with a verifier built from opts.
func verifyDocument(raw, nonce []byte, repo string, opts ...verify.Option) (*verify.Verification, error) {
	verifier, err := verify.NewVerifier(opts...)
	if err != nil {
		return nil, err
	}
	return verifier.VerifyV3(raw, nonce, verify.Pin{Repo: repo})
}

func TestLiveVerifyRegisterPins(t *testing.T) {
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	host, repo := os.Getenv(enclaveEnvVar), os.Getenv(repoEnvVar)
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	raw, err := fetch.Document(t.Context(), host, "", nonce)
	require.NoError(t, err)
	verified, err := verifyDocument(raw, nonce, repo)
	require.NoError(t, err)
	const maxAge = 30 * 24 * time.Hour
	for _, age := range []time.Duration{0, maxAge} {
		_, err := verifyDocument(raw, nonce, repo, verify.WithFreshnessMaxAge(age), verify.WithPinnedRegisters(exactPins(verified.EnclaveMeasurement(), nil)))
		require.NoError(t, err)
	}
	bad := measurement.Register{0xab}
	badPins := exactPins(verified.EnclaveMeasurement(), &bad)
	require.NotEqual(t, exactPins(verified.EnclaveMeasurement(), nil), badPins)
	_, err = verifyDocument(raw, nonce, repo, verify.WithPinnedRegisters(badPins))
	var rejected *verify.VerificationError
	require.ErrorAs(t, err, &rejected)
	v, err := verify.NewVerifier(verify.WithPinnedRegisters(badPins), verify.WithFreshnessMaxAge(maxAge))
	require.NoError(t, err)
	s, err := New(Config{Host: host, Pin: verify.Pin{Repo: repo}, Verifier: v})
	require.NoError(t, err)
	_, err = s.Verify()
	require.ErrorIs(t, err, errs.ErrAttestation)
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
