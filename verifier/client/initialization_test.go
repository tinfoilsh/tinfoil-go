package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
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

func TestDefaultClientReselectsOnRetryAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var discoveries int
		original := http.DefaultClient
		defer func() { http.DefaultClient = original }()
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			assert.Equal(t, defaultRouterURL, req.URL.String())
			discoveries++
			router := "unavailable.example"
			if discoveries == 2 {
				router = "first.example"
			} else if discoveries == 4 {
				router = "replacement.example"
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`["` + router + `"]`))}, nil
		})}
		opts := VerificationOptions{FreshnessMaxAge: 48 * time.Hour, PinnedRegisters: &measurement.Measurement{Type: measurement.TdxGuestV2, Registers: []string{4: measurement.RTMR3_ZERO}}}
		s, err := NewSecureClient(fallbackEnclave, defaultRouterRepo, &opts)
		require.NoError(t, err)
		s.autoSelect = true
		var probes []string
		s.verify = func(host string) (*VerifiedDocumentV3, error) {
			probes = append(probes, host)
			assert.Nil(t, s.Verification(), "failed initialization and rejected keys must not remain usable")
			assert.Equal(t, opts.FreshnessMaxAge, s.options.FreshnessMaxAge)
			assert.Equal(t, opts.PinnedRegisters, s.options.PinnedRegisters)
			if host == "unavailable.example" || host == "inference.tinfoil.sh" {
				return nil, &FetchError{Err: errors.New("unavailable")}
			}
			state := testState(time.Now().Add(time.Hour), host)
			state.EnclaveHost = host
			return state, nil
		}
		var sent []string
		transport, err := s.NewTransport(func(state *VerifiedDocumentV3) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				sent = append(sent, state.EnclaveHost)
				if state.EnclaveHost == "first.example" {
					return nil, errCertMismatch
				}
				return testResponse(), nil
			}), nil
		}, isCertificateError)
		require.NoError(t, err)
		require.Equal(t, "first.example", s.Enclave())
		req, _ := http.NewRequest(http.MethodGet, "https://first.example/v1/models", nil)
		_, err = transport.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, []string{"first.example", "replacement.example"}, sent)
		require.Equal(t, "replacement.example", s.Enclave())
		require.Equal(t, 4, discoveries)
		require.Equal(t, []string{"unavailable.example", "inference.tinfoil.sh", "first.example", "unavailable.example", "inference.tinfoil.sh", "replacement.example"}, probes)
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
				s.verify = func(string) (*VerifiedDocumentV3, error) {
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
		s := &SecureClient{verify: func(string) (*VerifiedDocumentV3, error) {
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

func TestVerificationAndFreshnessDoNotDiscoverRouters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var discoveries int
		original := http.DefaultClient
		defer func() { http.DefaultClient = original }()
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			discoveries++
			return nil, errors.New("verification must not discover routers")
		})}
		var probes []string
		s := &SecureClient{autoSelect: true, enclave: "selected.example", state: testState(time.Now().Add(time.Minute), "old"), verify: func(host string) (*VerifiedDocumentV3, error) {
			probes = append(probes, host)
			if len(probes)%2 == 1 {
				return nil, &FetchError{Err: errors.New("temporarily unavailable")}
			}
			state := testState(time.Now().Add(time.Minute), "fresh")
			state.EnclaveHost = host
			return state, nil
		}}
		_, err := s.Verify()
		require.NoError(t, err)
		transport, err := s.NewTransport(func(*VerifiedDocumentV3) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil }), nil
		}, nil)
		require.NoError(t, err)
		time.Sleep(time.Minute)
		req, _ := http.NewRequest(http.MethodGet, "https://selected.example", nil)
		_, err = transport.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, []string{"selected.example", "selected.example", "selected.example", "selected.example"}, probes)
		require.Zero(t, discoveries)
		require.Equal(t, "selected.example", s.Enclave())
	})
}

func TestFallbackDiagnostics(t *testing.T) {
	for _, discovery := range []string{"failure", "timeout", "oversized", "candidates"} {
		synctest.Test(t, func(t *testing.T) {
			discoveryCause, routerCause, fallbackCause := errors.New("discovery offline"), errors.New("router offline"), errors.New("fallback offline")
			original := http.DefaultClient
			defer func() { http.DefaultClient = original }()
			requests := make(map[string]int)
			http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests[req.URL.Host]++
				if req.URL.String() == defaultRouterURL {
					if discovery == "failure" {
						return nil, discoveryCause
					}
					if discovery == "timeout" {
						<-req.Context().Done()
						return nil, req.Context().Err()
					}
					if discovery == "oversized" {
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", maxRouterDiscoveryBytes+1)))}, nil
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`["router.example"]`))}, nil
				}
				if req.URL.Host == "router.example" {
					return nil, routerCause
				}
				return nil, fallbackCause
			})}
			start := time.Now()
			s, err := NewDefaultClient(nil)
			require.Nil(t, s, "failed client initialization must return its error")
			require.ErrorIs(t, err, fallbackCause)
			require.Equal(t, 2, requests["inference.tinfoil.sh"])
			require.Equal(t, 2, requests["atc.tinfoil.sh"], "retry repeats discovery")
			if discovery == "failure" {
				require.ErrorIs(t, err, discoveryCause)
			} else if discovery == "timeout" {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.Equal(t, 61*time.Second, time.Since(start), "a stuck discovery must release the shared recovery")
			} else if discovery == "oversized" {
				require.ErrorContains(t, err, "router discovery response exceeds")
			} else {
				require.ErrorIs(t, err, routerCause)
				require.Equal(t, 2, requests["router.example"], "one probe per candidate in each attempt")
			}
			s, err = NewSecureClient(fallbackEnclave, defaultRouterRepo, nil)
			require.NoError(t, err)
			s.autoSelect = true
			s.verify = func(host string) (*VerifiedDocumentV3, error) {
				if host == "router.example" {
					return nil, &FetchError{Err: routerCause}
				}
				state := testState(time.Now().Add(time.Hour), "fallback")
				state.EnclaveHost = host
				return state, nil
			}
			_, err = s.ready(context.Background(), nil)
			require.NoError(t, err, "a verified fallback suppresses earlier selection failures")
		})
	}
}

func TestRefreshRejectsExpiredPublication(t *testing.T) {
	s := &SecureClient{}
	deadline := make(chan time.Time, 1)
	s.verify = func(string) (*VerifiedDocumentV3, error) {
		s.stateMu.Lock()
		expires := time.Now().Add(20 * time.Millisecond)
		deadline <- expires
		return testState(expires, "late"), nil
	}
	call := &verificationCall{done: make(chan struct{})}
	go s.refresh(call, func() (*VerifiedDocumentV3, error) { return s.verify("") })
	// Keep publication blocked until after the otherwise valid result expires.
	time.Sleep(time.Until(<-deadline) + time.Millisecond)
	s.stateMu.Unlock()
	<-call.done
	require.ErrorIs(t, call.err, errFreshnessExpired)
	require.Nil(t, call.state)
	require.Nil(t, s.Verification())
}
