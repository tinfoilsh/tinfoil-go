package transport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// state is one successful verification and the round tripper created for its
// keys. They are published together, so a request never sends under keys
// other than those of the verification it checked.
type state struct {
	// report passed every step, so its VerifiedFacts are set.
	report       *verify.VerificationReport
	roundTripper http.RoundTripper
	// rejected is guarded by the Transport's mu.
	rejected bool
}

// valid is called with the Transport's mu held.
func (s *state) valid() bool {
	return !s.rejected && time.Now().Before(s.report.VerifiedFacts.FreshnessExpiresAt())
}

// attempt is the outcome of one attempt to verify the enclave: a report that
// passed, or the error that the transport reported.
type attempt struct {
	report *verify.VerificationReport
	err    error
}

// verifyFunc verifies an enclave, passing each failed attempt that it retries
// to retried.
type verifyFunc func(e *enclave.Enclave, retried func(error)) (*verify.VerificationReport, error)

// EnsureVerified returns the report of a verification that is valid now,
// verifying first only if the current one has expired or been invalidated. A
// nil error means requests can be sent under it.
func (t *Transport) EnsureVerified(ctx context.Context) (*verify.VerificationReport, error) {
	s, err := t.verified(ctx, false, (*enclave.Enclave).Verify)
	if err != nil {
		return nil, err
	}
	return s.report.Clone(), nil
}

// Reverify verifies again even if the current verification is still valid.
// An attestation failure discards the current verification, so that the next
// request verifies again; any other failure keeps it while it is still valid.
func (t *Transport) Reverify(ctx context.Context) (*verify.VerificationReport, error) {
	s, err := t.verified(ctx, true, (*enclave.Enclave).Verify)
	if err != nil {
		return nil, err
	}
	return s.report.Clone(), nil
}

// VerifyOnce verifies like Reverify but doesn't retry a failed attempt, so a
// caller trying several enclaves moves on quickly.
func (t *Transport) VerifyOnce(ctx context.Context) (*verify.VerificationReport, error) {
	s, err := t.verified(ctx, true, (*enclave.Enclave).VerifyOnce)
	if err != nil {
		return nil, err
	}
	return s.report.Clone(), nil
}

// CurrentVerification returns the report of the verification that requests
// are bound to now, without I/O: the current verification while it is fresh
// and has not been discarded or rejected, and otherwise nil.
func (t *Transport) CurrentVerification() *verify.VerificationReport {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if s := t.current; s != nil && s.valid() {
		return s.report.Clone()
	}
	return nil
}

// LastVerificationAttempt returns the outcome of the most recent attempt to
// verify the enclave, without I/O: its report if it passed, and otherwise no
// report and the error that the transport reported for it. Before the first
// attempt it returns neither. A report that it returns may have expired or
// been invalidated; CurrentVerification returns one that has not.
func (t *Transport) LastVerificationAttempt() (*verify.VerificationReport, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.last == nil {
		return nil, nil
	}
	return t.last.report.Clone(), t.last.err
}

// verified returns a valid state, refreshing it first when force is set or
// the current one is invalid. Concurrent callers share one refresh, including
// its failure.
func (t *Transport) verified(ctx context.Context, force bool, verify verifyFunc) (*state, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		t.mu.Lock()
		if s := t.current; s != nil && s.valid() && !force {
			t.mu.Unlock()
			return s, nil
		}
		// DoChan runs the refresh in its own goroutine, which takes mu only
		// after this caller releases it.
		refreshed := t.refreshes.DoChan("", func() (any, error) { return nil, t.refresh(verify) })
		t.mu.Unlock()

		// A caller's cancellation does not abort a refresh other callers need.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-refreshed:
			if result.Err != nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return nil, result.Err
			}
		}
		// A request can reject the new state before this caller wakes, so
		// check t.current again rather than trust the refresh's result.
		force = false
	}
}

// refresh verifies the enclave and publishes the result as the current state.
// A refresh that fails attestation discards the state that it was replacing:
// the enclave no longer proves that it holds that state's keys. Any other
// failure, such as a brief outage of the attestation source, keeps that state
// while it is still valid.
//
// Each attempt, retried or final, becomes the last verification as soon as
// its outcome is decided, and is reported to the enclave's OnVerification
// once the refresh is done, outside mu and outside the shared refresh: the
// refresh is forgotten first, so that a callback that calls EnsureVerified or
// Reverify starts a refresh of its own rather than waiting for the one that
// is calling it.
func (t *Transport) refresh(verify verifyFunc) error {
	t.mu.RLock()
	replacing := t.current
	t.mu.RUnlock()
	var attempts []*attempt
	retried := func(err error) {
		t.mu.Lock()
		t.last = &attempt{err: err}
		t.mu.Unlock()
		attempts = append(attempts, &attempt{err: err})
	}
	// The attestation fetch bounds its network I/O. Local verification has no
	// SDK deadline; each caller can independently cancel its wait above.
	verified, err := verify(t.enclave, retried)
	var s *state
	if err == nil {
		s, err = t.newState(verified)
	}
	last := t.publish(s, err, replacing)
	attempts = append(attempts, last)
	t.refreshes.Forget("")
	for _, a := range attempts {
		t.enclave.Notify(a.report.Clone(), a.err)
	}
	return last.err
}

// publish decides the outcome of a refresh that produced s, or failed with
// err, makes it the last verification, and returns it.
func (t *Transport) publish(s *state, err error, replacing *state) *attempt {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Creating the round tripper or waiting for mu can outlast freshness.
	if err == nil && !s.valid() {
		closeIdleConnections(s.roundTripper)
		err = errs.Attestation(enclave.ErrFreshnessExpired)
	}
	if err == nil {
		// Idle connections of the replaced state are tied to its keys.
		if t.current != nil {
			closeIdleConnections(t.current.roundTripper)
		}
		t.current = s
	}
	// Refreshes run one at a time, so only a refresh can have replaced the
	// state since this one began; the check keeps the rule explicit.
	if errors.Is(err, errs.ErrAttestation) && replacing != nil && t.current == replacing {
		t.discard(replacing)
	}
	t.last = &attempt{err: err}
	if err == nil {
		t.last.report = s.report
	}
	return t.last
}

// newState creates the mode's round tripper for r's verified facts.
func (t *Transport) newState(r *verify.VerificationReport) (*state, error) {
	// The mode gets a copy, so it can't change the facts kept here.
	facts := *r.VerifiedFacts
	rt, err := t.mode.newRoundTripper(&facts)
	if rt == nil && err == nil {
		err = fmt.Errorf("transport mode returned a nil round tripper")
	}
	if err != nil {
		closeIdleConnections(rt)
		return nil, err
	}
	return &state{report: r, roundTripper: rt}, nil
}

// discard marks s rejected, so that no request starts under it again, and
// closes its idle connections, which are tied to its keys. Requests already
// sent under it may complete. It is called with mu held.
func (t *Transport) discard(s *state) {
	s.rejected = true
	closeIdleConnections(s.roundTripper)
}

// invalidate marks s rejected, so the next request verifies again.
// Invalidating a replaced state leaves the current one valid.
func (t *Transport) invalidate(s *state) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s.rejected = true
}
