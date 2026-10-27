package enclave

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestInitializationRecovery(t *testing.T) {
	firstCause, lastCause := errors.New("first attempt"), errors.New("last attempt")
	for _, tc := range []struct {
		name        string
		first, last error
		attempts    int
	}{
		{"fetch then success", &NetworkError{Err: firstCause}, nil, 2},
		{"attestation then success", &AttestationError{Err: firstCause}, nil, 2},
		{"both attempts fail", &NetworkError{Err: firstCause}, &AttestationError{Err: lastCause}, 2},
		{"configuration", &ConfigurationError{Err: firstCause}, nil, 1},
		{"native error", firstCause, nil, 1},
		{"native error with fetch diagnostics", errors.Join(firstCause, &NetworkError{Err: lastCause}), nil, 1},
		{"configuration among causes", errors.Join(&NetworkError{Err: lastCause}, &ConfigurationError{Err: firstCause}), nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := &Handle{}
				var attempts int
				s.verify = func() (*verify.Verification, error) {
					attempts++
					assert.Nil(t, current(s), "failed attempts must not publish state")
					if attempts == 1 {
						return testState(time.Now().Add(time.Hour), "rejected"), tc.first
					}
					return testState(time.Now().Add(time.Hour), "fresh"), tc.last
				}
				start := time.Now()
				verified, err := verifyNow(s)
				require.Equal(t, tc.attempts, attempts)
				require.Equal(t, time.Duration(attempts-1)*time.Second, time.Since(start))
				if attempts == 2 && tc.last == nil {
					require.NoError(t, err)
					require.Equal(t, "fresh", verified.CodeTag())
				} else {
					require.ErrorIs(t, err, firstCause)
					if tc.last != nil {
						require.ErrorIs(t, err, lastCause)
					}
					require.Nil(t, current(s))
				}
			})
		})
	}
}

func TestInitializationRetryIsShared(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts int
		release := make(chan struct{})
		s := &Handle{verify: func() (*verify.Verification, error) {
			attempts++
			if attempts == 1 {
				<-release
				return nil, &NetworkError{Err: errors.New("temporarily unavailable")}
			}
			return testState(time.Now().Add(time.Hour), "fresh"), nil
		}}
		results := make(chan error, 8)
		for range cap(results) {
			go func() { _, err := verifyNow(s); results <- err }()
		}
		synctest.Wait()
		close(release)
		for range cap(results) {
			require.NoError(t, <-results)
		}
		require.Equal(t, 2, attempts)
	})
}

func TestRefreshRejectsExpiredPublication(t *testing.T) {
	s := &Handle{}
	deadline := make(chan time.Time, 1)
	s.verify = func() (*verify.Verification, error) {
		s.stateMu.Lock()
		expires := time.Now().Add(20 * time.Millisecond)
		deadline <- expires
		return testState(expires, "late"), nil
	}
	call := &verificationCall{done: make(chan struct{})}
	go s.refresh(call, verificationRetries)
	// Keep publication blocked until after the otherwise valid result expires.
	time.Sleep(time.Until(<-deadline) + time.Millisecond)
	s.stateMu.Unlock()
	<-call.done
	require.ErrorIs(t, call.err, ErrFreshnessExpired)
	require.Nil(t, call.state)
	require.Nil(t, current(s))
}
