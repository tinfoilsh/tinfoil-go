package verify

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

func TestNewDefaults(t *testing.T) {
	v, err := NewVerifier()
	require.NoError(t, err)
	assert.Equal(t, endorsement.MaxFreshnessAge, v.FreshnessMaxAge())
	assert.Nil(t, v.PinnedRegisters())
}

func TestWithFreshnessMaxAge(t *testing.T) {
	// Zero keeps the default, so a caller passing an unset policy field does
	// not silently disable the bound.
	v, err := NewVerifier(WithFreshnessMaxAge(0))
	require.NoError(t, err)
	assert.Equal(t, endorsement.MaxFreshnessAge, v.FreshnessMaxAge())

	v, err = NewVerifier(WithFreshnessMaxAge(24 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, v.FreshnessMaxAge())

	for _, maxAge := range []time.Duration{-time.Nanosecond, -time.Hour} {
		v, err := NewVerifier(WithFreshnessMaxAge(maxAge))
		require.Nil(t, v)
		require.ErrorContains(t, err, "freshness maximum age must not be negative")
		var usage *UsageError
		require.ErrorAs(t, err, &usage)
	}
}

func TestWithPinnedRegistersCopies(t *testing.T) {
	register := measurement.Register{0xab}
	pinned := register
	v, err := NewVerifier(WithPinnedRegisters(measurement.ExpectedTDX{RTMR3: &pinned}))
	require.NoError(t, err)

	// Changing the caller's register after construction must not reach the
	// policy, and the accessor must hand back a copy for the same reason.
	pinned[0] = 0xcd
	got := v.PinnedRegisters().(measurement.ExpectedTDX)
	assert.Equal(t, register, *got.RTMR3)
	*got.RTMR3 = measurement.Register{0xef}
	assert.Equal(t, register, *v.PinnedRegisters().(measurement.ExpectedTDX).RTMR3)
}

// Pins are values. A pointer, nil or not, satisfies measurement.Expected but
// is a usage error.
func TestWithPinnedRegistersRejectsPointers(t *testing.T) {
	register := measurement.Register{0xab}
	for name, pins := range map[string]measurement.Expected{
		"SEV-SNP":     &measurement.ExpectedSEVSNP{Launch: &register},
		"TDX":         &measurement.ExpectedTDX{RTMR3: &register},
		"nil SEV-SNP": (*measurement.ExpectedSEVSNP)(nil),
		"nil TDX":     (*measurement.ExpectedTDX)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := NewVerifier(WithPinnedRegisters(pins))
			require.Nil(t, v)
			require.ErrorAs(t, err, new(*UsageError))
			require.ErrorContains(t, err, "value, not *measurement.Expected")
		})
	}
}

// Pins apply only to the platform the quote proves: a register the enclave
// really measured verifies when pinned for its platform and rejects when
// pinned for the other one.
func TestLivePinsForTheOtherPlatformReject(t *testing.T) {
	const enclaveEnvVar, repoEnvVar = "TINFOIL_ENCLAVE", "TINFOIL_REPO"
	testutil.RequireLive(t, enclaveEnvVar, repoEnvVar)
	repo := os.Getenv(repoEnvVar)
	nonce, err := document.RandomNonce()
	require.NoError(t, err)
	raw, err := fetch.Document(t.Context(), os.Getenv(enclaveEnvVar), "", nonce)
	require.NoError(t, err)
	verifier, err := NewVerifier()
	require.NoError(t, err)
	verified, err := verifier.VerifyV3(raw, nonce, repo)
	require.NoError(t, err)

	var own, other measurement.Expected
	switch m := verified.EnclaveMeasurement().(type) {
	case measurement.SEVSNP:
		own, other = measurement.ExpectedSEVSNP{Launch: &m.Launch}, measurement.ExpectedTDX{MRTD: &m.Launch}
	case measurement.TDX:
		own, other = measurement.ExpectedTDX{MRTD: &m.MRTD}, measurement.ExpectedSEVSNP{Launch: &m.MRTD}
	default:
		t.Fatalf("unexpected enclave measurement %T", m)
	}
	pinned, err := NewVerifier(WithPinnedRegisters(own))
	require.NoError(t, err)
	_, err = pinned.VerifyV3(raw, nonce, repo)
	require.NoError(t, err)

	pinned, err = NewVerifier(WithPinnedRegisters(other))
	require.NoError(t, err)
	_, err = pinned.VerifyV3(raw, nonce, repo)
	var rejected *VerificationError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, LayerPolicy, rejected.Layer)
	require.ErrorContains(t, err, "pinned registers are for")
}

func TestVerifyV3RejectsBadRepo(t *testing.T) {
	v, err := NewVerifier()
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, Collateral: []collateral.Entry{{
		ID: "code", Role: collateral.RoleReferenceValues, Format: collateral.SigstoreCodeV1Format,
		Data: []byte(`{"digest":"digest","sigstore_bundle":{}}`),
	}}}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	verified, err := v.VerifyV3(raw, nonce, "not a repo reference")
	require.Nil(t, verified)
	var usage *UsageError
	require.ErrorAs(t, err, &usage)
}

func TestNewIgnoresNilOption(t *testing.T) {
	v, err := NewVerifier(nil, WithFreshnessMaxAge(time.Hour), nil)
	require.NoError(t, err)
	assert.Equal(t, time.Hour, v.FreshnessMaxAge())
}

// A caller that ignores NewVerifier's error holds a nil *Verifier, and a zero
// value carries neither a trust root nor a clock. Verifying with either must
// report a usage error rather than panicking once a well-formed
// document gets past the parse and the receiver is first dereferenced.
func TestVerifyV3RejectsUnbuiltVerifier(t *testing.T) {
	for name, v := range map[string]*Verifier{"nil": nil, "zero value": {}} {
		t.Run(name, func(t *testing.T) {
			verified, err := v.VerifyV3([]byte("{}"), make([]byte, 32), "org/repo")
			require.Nil(t, verified)
			var usage *UsageError
			require.ErrorAs(t, err, &usage)
			require.ErrorContains(t, err, "verifier must be built with NewVerifier")
		})
	}
}
