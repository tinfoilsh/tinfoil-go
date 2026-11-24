package transport

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// currentTag returns the code tag of tr's current verification, or "" when
// it has none.
func currentTag(tr *Transport) string {
	if r := tr.CurrentVerification(); r != nil {
		return r.VerifiedFacts.CodeTag()
	}
	return ""
}

func TestCurrentVerificationBeforeTheFirstSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fetch, _ := verifications(failing(errBadDocument), fresh("key"))
		transport, _ := newObservedTransport(fetch, sendOK)
		require.Nil(t, transport.CurrentVerification(), "nothing before the first attempt")

		_, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err, "the retry succeeds")
		require.Equal(t, "key", currentTag(transport))

		failed, _ := newObservedTransport(failing(errBadDocument), sendOK)
		_, err = failed.EnsureVerified(context.Background())
		require.ErrorIs(t, err, errs.ErrAttestation)
		require.Nil(t, failed.CurrentVerification(), "nothing after a first verification that fails")
	})
}

func TestCurrentVerificationIsTheFreshVerification(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport, _ := newObservedTransport(fresh("key"), sendOK)
		ensured, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err)

		current := transport.CurrentVerification()
		require.Equal(t, ensured, current)
		last, err := transport.LastVerificationAttempt()
		require.NoError(t, err)
		require.Equal(t, last, current)

		current.VerifiedFacts = nil
		require.Equal(t, ensured, transport.CurrentVerification(), "the report is a copy")
	})
}

// A re-verification that fails without discarding the verification leaves
// it current while it is fresh, though the last attempt is the failure.
func TestCurrentVerificationAfterANetworkFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		unreachable := errs.Network(errors.New("attestation source unavailable"))
		fetch, _ := verifications(func() (*verify.VerificationReport, error) {
			return testState(time.Now().Add(time.Hour), "old"), nil
		}, failing(unreachable))
		transport, _ := newObservedTransport(fetch, sendOK)
		ensured, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err)

		_, err = transport.Reverify(context.Background())
		require.ErrorIs(t, err, errs.ErrNetwork)
		require.Equal(t, ensured, transport.CurrentVerification(), "requests are still bound to the cached verification")
		last, lastErr := transport.LastVerificationAttempt()
		require.Nil(t, last)
		require.Same(t, err, lastErr, "the last attempt is the failure")
		require.NoError(t, send(t, transport), "requests still go through")

		time.Sleep(2 * time.Hour)
		require.Nil(t, transport.CurrentVerification(), "until it expires")
	})
}

func TestCurrentVerificationAfterAnAttestationFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Verify retries once, so the re-verification fails twice.
		fetch, _ := verifications(fresh("old"), failing(errBadDocument), failing(errBadDocument), fresh("new"))
		transport, _ := newObservedTransport(fetch, sendOK)
		_, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err)

		_, err = transport.Reverify(context.Background())
		require.ErrorIs(t, err, errs.ErrAttestation)
		require.Nil(t, transport.CurrentVerification(), "the failure discarded the verification")
		_, lastErr := transport.LastVerificationAttempt()
		require.Same(t, err, lastErr)

		require.NoError(t, send(t, transport), "the next request verifies again")
		require.Equal(t, "new", currentTag(transport))
	})
}

func TestCurrentVerificationAfterAKeyRejection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		transport, _ := newObservedTransport(fresh("key"), sendOK)
		_, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err)
		invalidateCurrent(transport)
		require.Nil(t, transport.CurrentVerification(), "no request is sent under rejected keys")
	})
}

// The client doesn't verify again in the background, so an expired
// verification leaves nothing current until the next verification.
func TestCurrentVerificationAfterExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fetch, calls := verifications(func() (*verify.VerificationReport, error) {
			return testState(time.Now().Add(time.Minute), "old"), nil
		}, fresh("new"))
		transport, _ := newObservedTransport(fetch, sendOK)
		ensured, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err)

		time.Sleep(time.Minute)
		require.Nil(t, transport.CurrentVerification(), "nil at the freshness deadline")
		last, err := transport.LastVerificationAttempt()
		require.NoError(t, err)
		require.Equal(t, ensured, last, "the last attempt is still the expired success")
		require.Equal(t, 1, *calls, "reading it doesn't verify")

		_, err = transport.EnsureVerified(context.Background())
		require.NoError(t, err)
		require.Equal(t, "new", currentTag(transport))
	})
}
