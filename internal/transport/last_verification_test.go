package transport

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// observed is one OnVerificationAttempt call.
type observed struct {
	host   string
	report *verify.VerificationReport
	err    error
}

// observer records OnVerificationAttempt calls.
type observer struct {
	mu    sync.Mutex
	calls []observed
}

func (o *observer) onVerification(host string, report *verify.VerificationReport, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, observed{host, report, err})
}

func (o *observer) all() []observed {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]observed(nil), o.calls...)
}

// newObservedTransport is newTestTransport with no initial verification,
// reporting each attempt to an observer.
func newObservedTransport(fetch func() (*verify.VerificationReport, error), m mode) (*Transport, *observer) {
	o := &observer{}
	return &Transport{enclave: enclave.NewForTest("enclave.example", fetch, o.onVerification), mode: m}, o
}

// errRejected is the error that the client reports when the verifier rejects
// a document.
func errRejected() error {
	return errs.Attestation(verifytest.Rejected("report signature is invalid"))
}

func TestLastVerificationAttemptBeforeAnyAttempt(t *testing.T) {
	transport, o := newObservedTransport(fresh("key"), sendOK)
	report, err := transport.LastVerificationAttempt()
	require.Nil(t, report)
	require.NoError(t, err)
	require.Empty(t, o.all())
}

func TestInitialVerificationIsReported(t *testing.T) {
	transport, o := newObservedTransport(fresh("key"), sendOK)
	ensured, err := transport.EnsureVerified(context.Background())
	require.NoError(t, err)

	last, err := transport.LastVerificationAttempt()
	require.NoError(t, err)
	require.NotNil(t, last.VerifiedFacts)
	require.Equal(t, "key", last.VerifiedFacts.CodeTag())
	require.Equal(t, ensured, last)

	calls := o.all()
	require.Len(t, calls, 1)
	require.Equal(t, "enclave.example", calls[0].host)
	require.NoError(t, calls[0].err)
	require.Equal(t, last, calls[0].report)
	require.NotSame(t, last, calls[0].report, "the callback gets its own copy")
}

func TestRejectedVerificationIsReported(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rejected := errRejected()
		transport, o := newObservedTransport(failing(rejected), sendOK)
		_, err := transport.EnsureVerified(context.Background())
		testutil.RequireCategory(t, err, errs.ErrAttestation)
		var verr *verify.VerificationError
		require.ErrorAs(t, err, &verr)
		failed, ok := verr.Report.Failed()
		require.True(t, ok)
		require.Equal(t, verify.LayerQuote, failed.Layer)
		require.NotNil(t, verr.Report.PartialFacts)

		last, lastErr := transport.LastVerificationAttempt()
		require.Nil(t, last)
		require.Same(t, err, lastErr, "the error that the client reported")

		// Verify retries an attestation failure once, and each attempt is
		// reported.
		calls := o.all()
		require.Len(t, calls, 2)
		require.Same(t, rejected, calls[0].err)
		require.Same(t, err, calls[1].err)
		for _, c := range calls {
			require.Nil(t, c.report)
			require.ErrorAs(t, c.err, &verr)
		}
	})
}

func TestFailedFetchHasNoReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		unreachable := errs.Network(errors.New("connection refused"))
		transport, o := newObservedTransport(failing(unreachable), sendOK)
		_, err := transport.EnsureVerified(context.Background())
		testutil.RequireCategory(t, err, errs.ErrNetwork)

		last, lastErr := transport.LastVerificationAttempt()
		require.Nil(t, last)
		require.Same(t, err, lastErr)
		require.NotErrorAs(t, lastErr, new(*verify.VerificationError))
		calls := o.all()
		require.Len(t, calls, 2)
		require.Same(t, err, calls[1].err)
		require.Nil(t, calls[1].report)
	})
}

// A failed re-verification replaces an earlier success, whether the failure
// discards the cached verification (attestation) or keeps it (network).
func TestFailedReverifyIsTheLastVerificationAttempt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failure  error
		category error
		keeps    bool
	}{
		{"attestation", errRejected(), errs.ErrAttestation, false},
		{"network", errs.Network(errors.New("temporarily unavailable")), errs.ErrNetwork, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				fetch, _ := verifications(fresh("old"), failing(tc.failure), failing(tc.failure))
				transport, o := newObservedTransport(fetch, sendOK)
				_, err := transport.EnsureVerified(context.Background())
				require.NoError(t, err)

				_, err = transport.Reverify(context.Background())
				testutil.RequireCategory(t, err, tc.category)
				last, lastErr := transport.LastVerificationAttempt()
				require.Nil(t, last, "never an earlier success in place of a later failure")
				require.Same(t, err, lastErr)
				require.Equal(t, tc.keeps, currentValid(transport))
				require.Len(t, o.all(), 3)
			})
		})
	}
}

func TestRetriedVerificationReportsEachAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := errRejected()
		fetch, _ := verifications(failing(first), fresh("key"))
		transport, o := newObservedTransport(fetch, sendOK)
		_, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err)

		calls := o.all()
		require.Len(t, calls, 2)
		require.Same(t, first, calls[0].err)
		require.Nil(t, calls[0].report)
		require.NoError(t, calls[1].err)
		require.Equal(t, "key", calls[1].report.VerifiedFacts.CodeTag())
		last, err := transport.LastVerificationAttempt()
		require.NoError(t, err)
		require.Equal(t, calls[1].report, last)
	})
}

// While the retry runs, the failed first attempt is the last verification.
func TestLastVerificationAttemptDuringARetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first := errRejected()
		release := make(chan struct{})
		var attempts int
		transport, _ := newObservedTransport(func() (*verify.VerificationReport, error) {
			attempts++
			if attempts == 1 {
				return nil, first
			}
			<-release
			return testState(time.Now().Add(time.Hour), "key"), nil
		}, sendOK)
		done := make(chan error)
		go func() { _, err := transport.EnsureVerified(context.Background()); done <- err }()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		_, err := transport.LastVerificationAttempt()
		require.Same(t, first, err)
		close(release)
		require.NoError(t, <-done)
		_, err = transport.LastVerificationAttempt()
		require.NoError(t, err)
	})
}

// A key rejection invalidates the verification, and the re-verification that
// the next request triggers is an attempt like any other.
func TestReverificationAfterKeyRejectionIsReported(t *testing.T) {
	fetch, _ := verifications(fresh("old"), fresh("new"))
	transport, o := newObservedTransport(fetch, sendOK)
	require.NoError(t, send(t, transport))
	invalidateCurrent(transport)
	require.NoError(t, send(t, transport))

	calls := o.all()
	require.Len(t, calls, 2)
	require.Equal(t, "enclave.example", calls[1].host)
	require.Equal(t, "new", calls[1].report.VerifiedFacts.CodeTag())
}

func TestSharedVerificationIsOneAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		transport, o := newObservedTransport(func() (*verify.VerificationReport, error) {
			<-release
			return testState(time.Now().Add(time.Hour), "key"), nil
		}, sendOK)
		results := make(chan error, 8)
		for range cap(results) {
			go func() { results <- send(t, transport) }()
		}
		synctest.Wait()
		close(release)
		for range cap(results) {
			require.NoError(t, <-results)
		}
		require.Len(t, o.all(), 1)
	})
}

// The callback runs outside the transport's lock, so it can call the
// transport, and sees the attempt that it was called for.
func TestOnVerificationAttemptCanCallTheTransport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var transport *Transport
		type seen struct {
			report *verify.VerificationReport
			err    error
		}
		var inCallback []seen
		fetch, _ := verifications(fresh("key"), failing(errRejected()), failing(errRejected()))
		transport = &Transport{mode: sendOK, enclave: enclave.NewForTest("enclave.example", fetch, func(_ string, report *verify.VerificationReport, err error) {
			lastReport, lastErr := transport.LastVerificationAttempt()
			inCallback = append(inCallback, seen{lastReport, lastErr})
			// EnsureVerified needs no refresh while the verification is
			// valid, and the callback holds no lock that it waits for.
			if err == nil {
				_, ensureErr := transport.EnsureVerified(context.Background())
				assert.NoError(t, ensureErr)
			}
		})}
		_, err := transport.EnsureVerified(context.Background())
		require.NoError(t, err)
		_, err = transport.Reverify(context.Background())
		require.Error(t, err)
		require.Len(t, inCallback, 3)
		require.NotNil(t, inCallback[0].report, "the attempt that the callback was called for")
		// The retried attempt is reported once the refresh is done, when the
		// last verification is already the later, final attempt.
		require.Same(t, err, inCallback[1].err)
		require.Same(t, err, inCallback[2].err)
	})
}

// A mode that can't use the keys fails the attempt after the verifier
// passed: the attempt has no report.
func TestRoundTripperFailureIsReportedWithoutAReport(t *testing.T) {
	newErr := errs.Attestation(errors.New("unusable key"))
	transport, o := newObservedTransport(fresh("key"), testMode(func(*verify.VerifiedFacts) (http.RoundTripper, error) { return nil, newErr }))
	_, err := transport.EnsureVerified(context.Background())
	require.ErrorIs(t, err, newErr)
	last, lastErr := transport.LastVerificationAttempt()
	require.Nil(t, last)
	require.Same(t, err, lastErr)
	calls := o.all()
	require.Len(t, calls, 1)
	require.Nil(t, calls[0].report)
}

// A callback that verifies again after a failed attempt starts a refresh of
// its own rather than waiting for the one that is calling it.
func TestOnVerificationAttemptCanVerifyAgainAfterAFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var transport *Transport
		fetch, _ := verifications(failing(errRejected()), failing(errRejected()), fresh("key"))
		var calls int
		var again *verify.VerificationReport
		transport = &Transport{mode: sendOK, enclave: enclave.NewForTest("enclave.example", fetch, func(_ string, _ *verify.VerificationReport, err error) {
			calls++
			if calls == 2 {
				var againErr error
				again, againErr = transport.EnsureVerified(context.Background())
				assert.NoError(t, againErr)
			}
		})}
		_, err := transport.EnsureVerified(context.Background())
		require.Error(t, err)
		require.NotNil(t, again)
		require.Equal(t, "key", again.VerifiedFacts.CodeTag())
		require.Equal(t, 3, calls)
	})
}

func TestOnVerificationAttemptPanicIsRecovered(t *testing.T) {
	calls := 0
	onVerification := func(string, *verify.VerificationReport, error) {
		calls++
		panic("callback bug")
	}
	transport := &Transport{enclave: enclave.NewForTest("enclave.example", fresh("key"), onVerification), mode: sendOK}

	report, err := transport.EnsureVerified(context.Background())
	require.NoError(t, err, "a panic in the callback doesn't change the outcome")
	require.Equal(t, "key", report.VerifiedFacts.CodeTag())
	require.Equal(t, 1, calls)

	last, err := transport.LastVerificationAttempt()
	require.NoError(t, err)
	require.Equal(t, report, last)

	// The transport still works: a later verification runs and is reported.
	_, err = transport.Reverify(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, calls)
}
