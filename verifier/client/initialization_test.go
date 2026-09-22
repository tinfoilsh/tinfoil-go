package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultClientProbesOncePerDiscovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cause := errors.New("unavailable")
		requests := make(map[string]int)
		original := http.DefaultClient
		defer func() { http.DefaultClient = original }()
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests[req.URL.Host]++
			if req.URL.String() == defaultRouterURL {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`["router.example"]`))}, nil
			}
			return nil, cause
		})}
		s, err := NewDefaultClient(nil)
		if err == nil {
			// Complete initialization if the constructor returned a lazy fallback.
			_, err = s.Verify()
		}
		require.ErrorIs(t, err, cause)
		require.Positive(t, requests["atc.tinfoil.sh"])
		require.Equal(t, requests["atc.tinfoil.sh"], requests["router.example"], "one candidate probe per discovery")
		require.Equal(t, 2, requests["inference.tinfoil.sh"], "fallback verification has one retry")
	})
}

func TestInitializationRecovery(t *testing.T) {
	firstCause, lastCause := errors.New("first attempt"), errors.New("last attempt")
	for _, tc := range []struct {
		name        string
		first, last error
		attempts    int
	}{
		{"fetch then success", &FetchError{Err: firstCause}, nil, 2},
		{"attestation then success", &AttestationError{Err: firstCause}, nil, 2},
		{"both attempts fail", &FetchError{Err: firstCause}, &AttestationError{Err: lastCause}, 2},
		{"configuration", &ConfigurationError{Err: firstCause}, nil, 1},
		{"native error", firstCause, nil, 1},
		{"native error with fetch diagnostics", errors.Join(firstCause, &FetchError{Err: lastCause}), nil, 1},
		{"configuration among causes", errors.Join(&FetchError{Err: lastCause}, &ConfigurationError{Err: firstCause}), nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := &SecureClient{}
				var attempts int
				s.verify = func() (*VerifiedDocumentV3, error) {
					attempts++
					assert.Nil(t, s.Verification(), "failed attempts must not publish state")
					if attempts == 1 {
						return testState(time.Now().Add(time.Hour), "rejected"), tc.first
					}
					return testState(time.Now().Add(time.Hour), "fresh"), tc.last
				}
				start := time.Now()
				verified, err := s.Verify()
				require.Equal(t, tc.attempts, attempts)
				require.Equal(t, time.Duration(attempts-1)*time.Second, time.Since(start))
				if attempts == 2 && tc.last == nil {
					require.NoError(t, err)
					require.Equal(t, "fresh", verified.CodeTag)
				} else {
					require.ErrorIs(t, err, firstCause)
					if tc.last != nil {
						require.ErrorIs(t, err, lastCause)
					}
					require.Nil(t, s.Verification())
				}
			})
		})
	}
}

func TestInitializationRetryIsShared(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempts int
		release := make(chan struct{})
		s := &SecureClient{verify: func() (*VerifiedDocumentV3, error) {
			attempts++
			if attempts == 1 {
				<-release
				return nil, &FetchError{Err: errors.New("temporarily unavailable")}
			}
			return testState(time.Now().Add(time.Hour), "fresh"), nil
		}}
		results := make(chan error, 8)
		for range cap(results) {
			go func() { _, err := s.Verify(); results <- err }()
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
	s := &SecureClient{}
	deadline := make(chan time.Time, 1)
	s.verify = func() (*VerifiedDocumentV3, error) {
		s.stateMu.Lock()
		expires := time.Now().Add(20 * time.Millisecond)
		deadline <- expires
		return testState(expires, "late"), nil
	}
	call := &verificationCall{done: make(chan struct{})}
	go s.refresh(call)
	// Keep publication blocked until after the otherwise valid result expires.
	time.Sleep(time.Until(<-deadline) + time.Millisecond)
	s.stateMu.Unlock()
	<-call.done
	require.ErrorIs(t, call.err, errFreshnessExpired)
	require.Nil(t, call.state)
	require.Nil(t, s.Verification())
}
