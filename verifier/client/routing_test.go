package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCachedEnclavesRemainIndependent(t *testing.T) {
	attempts := make(map[string]int)
	failed := errors.New("verification failed")
	s, err := NewSecureClient("a.example", "org/repo", nil)
	require.NoError(t, err)
	s.verify = func(enclave string) (*VerifiedDocumentV3, error) {
		attempts[enclave]++
		if enclave == "bad.example" {
			return nil, failed
		}
		return testState(time.Now().Add(time.Hour), enclave), nil
	}
	transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := testResponse()
			resp.Header.Set("Enclave", verified.EnclaveHost)
			return resp, nil
		}), nil
	}, nil)
	require.NoError(t, err)
	initial := s.enclaves["a.example"].state
	adapter := transport.(*refreshingTransport)
	for _, target := range []string{"b.example", "bad.example", "a.example"} {
		state, err := s.prepareTransport(context.Background(), target, adapter, verificationRetries)
		if target == "bad.example" {
			require.ErrorIs(t, err, failed)
			require.NotContains(t, s.enclaves, target)
			continue
		}
		require.NoError(t, err)
		req, _ := http.NewRequest(http.MethodGet, "https://"+target, nil)
		resp, err := state.transports[adapter].RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, target, resp.Header.Get("Enclave"))
		resp.Body.Close()
	}
	require.Equal(t, map[string]int{"a.example": 1, "b.example": 1, "bad.example": 1}, attempts)
	require.Same(t, initial, s.enclaves["a.example"].state)
	require.Equal(t, "a.example", s.Enclave(), "preparing another enclave does not select it")
	s.invalidate(initial)
	require.True(t, s.enclaves["b.example"].state.valid())
}

func TestRouterSelectionOnlyOnDefaultKeyRecovery(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		t.Run(fmt.Sprintf("automatic=%t", automatic), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var discoveries int
				original := http.DefaultClient
				t.Cleanup(func() { http.DefaultClient = original })
				http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					discoveries++
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`["b.example"]`))}, nil
				})}
				s, err := NewSecureClient("a.example", "org/repo", &VerificationOptions{FreshnessMaxAge: time.Hour})
				require.NoError(t, err)
				s.autoSelect = automatic
				attempts := make(map[string]int)
				s.verify = func(enclave string) (*VerifiedDocumentV3, error) {
					attempts[enclave]++
					require.Equal(t, time.Hour, s.options.FreshnessMaxAge)
					return testState(time.Now().Add(time.Hour), fmt.Sprintf("%s/%d", enclave, attempts[enclave])), nil
				}
				transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
					return roundTripFunc(func(*http.Request) (*http.Response, error) {
						if verified.CodeTag == "a.example/1" {
							return nil, errCertMismatch
						}
						return testResponse(), nil
					}), nil
				}, isCertificateError)
				require.NoError(t, err)
				req, _ := http.NewRequest(http.MethodGet, "https://a.example", nil)
				_, err = transport.RoundTrip(req)
				require.NoError(t, err)
				expected, discoveryCount := "a.example", 0
				if automatic {
					expected, discoveryCount = "b.example", 1
				}
				require.Equal(t, expected, s.Enclave())
				_, err = s.Verify()
				require.NoError(t, err)
				time.Sleep(time.Hour)
				_, err = transport.RoundTrip(req)
				require.NoError(t, err)
				require.Equal(t, discoveryCount, discoveries)
			})
		})
	}
}

func TestTLSRecoveryRoutesToNewRouter(t *testing.T) {
	for _, useProxy := range []bool{false, true} {
		t.Run(fmt.Sprintf("CONNECT=%t", useProxy), func(t *testing.T) {
			old := newECDSATLSServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("the old router must reject the obsolete key before sending the request")
			}))
			defer old.Close()
			var sends atomic.Int32
			next := newECDSATLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Equal(t, "payload", string(body))
				require.Equal(t, "/v1/chat?stream=true", r.URL.String())
				require.Equal(t, "Bearer test", r.Header.Get("Authorization"))
				w.WriteHeader(http.StatusNoContent)
			}))
			defer next.Close()
			roots := x509.NewCertPool()
			roots.AddCert(old.Certificate())
			roots.AddCert(next.Certificate())
			base := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
			if useProxy {
				proxy := newConnectProxy()
				defer proxy.Close()
				proxyURL, err := url.Parse(proxy.URL)
				require.NoError(t, err)
				base.Proxy = http.ProxyURL(proxyURL)
			}
			original := http.DefaultTransport
			http.DefaultTransport = base
			defer func() { http.DefaultTransport = original; base.CloseIdleConnections() }()
			key, err := CertPubkeyFP(next.Certificate())
			require.NoError(t, err)
			oldState := testState(time.Now().Add(time.Hour), "obsolete-key")
			oldState.EnclaveHost = strings.TrimPrefix(old.URL, "https://")
			s := &SecureClient{enclave: oldState.EnclaveHost, autoSelect: true, enclaves: map[string]*enclaveEntry{oldState.EnclaveHost: {state: &enclaveState{VerifiedDocumentV3: oldState}}}}
			// Discovery itself is covered separately; provide its newly verified result.
			originalHTTP := http.DefaultClient
			http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`["` + strings.TrimPrefix(next.URL, "https://") + `"]`))}, nil
			})}
			defer func() { http.DefaultClient = originalHTTP }()
			s.verify = func(host string) (*VerifiedDocumentV3, error) {
				state := testState(time.Now().Add(time.Hour), key)
				state.EnclaveHost = host
				return state, nil
			}
			hc, err := s.HTTPClient()
			require.NoError(t, err)
			defer hc.CloseIdleConnections()
			for range 2 {
				req, _ := http.NewRequest(http.MethodPost, old.URL+"/v1/chat?stream=true", bytes.NewBufferString("payload"))
				req.Header.Set("Authorization", "Bearer test")
				resp, err := hc.Do(req)
				require.NoError(t, err)
				resp.Body.Close()
				require.Equal(t, old.URL+"/v1/chat?stream=true", req.URL.String(), "do not mutate the original request")
				require.Equal(t, strings.TrimPrefix(next.URL, "https://"), s.Enclave())
			}
			require.EqualValues(t, 2, sends.Load(), "each request reaches the new router once")
		})
	}
}

func TestRouterRecoveryPreparesEachWaitingTransport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		original := http.DefaultClient
		t.Cleanup(func() { http.DefaultClient = original })
		var discoveries int
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			discoveries++
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`["b.example"]`))}, nil
		})}
		s, err := NewSecureClient("a.example", "org/repo", nil)
		require.NoError(t, err)
		s.autoSelect = true
		release := make(chan struct{})
		s.verify = func(enclave string) (*VerifiedDocumentV3, error) {
			if enclave == "b.example" {
				<-release
			}
			return testState(time.Now().Add(time.Hour), enclave), nil
		}
		var transports []http.RoundTripper
		for _, name := range []string{"first", "second"} {
			transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
				return roundTripFunc(func(*http.Request) (*http.Response, error) {
					if verified.EnclaveHost == "a.example" {
						return nil, errCertMismatch
					}
					resp := testResponse()
					resp.Header.Set("Transport", name)
					return resp, nil
				}), nil
			}, isCertificateError)
			require.NoError(t, err)
			transports = append(transports, transport)
		}
		results := make(chan *http.Response, len(transports))
		for _, transport := range transports {
			go func() {
				req, _ := http.NewRequest(http.MethodGet, "https://a.example", nil)
				resp, err := transport.RoundTrip(req)
				assert.NoError(t, err)
				results <- resp
			}()
		}
		synctest.Wait()
		close(release)
		var names []string
		for range transports {
			resp := <-results
			require.NotNil(t, resp)
			names = append(names, resp.Header.Get("Transport"))
		}
		require.ElementsMatch(t, []string{"first", "second"}, names)
		require.Equal(t, 1, discoveries)
	})
}

func TestPendingRouterSelectionDoesNotReplaceNewerSelection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		original := http.DefaultClient
		t.Cleanup(func() { http.DefaultClient = original })
		next := "b.example"
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%q]", next)))}, nil
		})}
		s, err := NewSecureClient("a.example", "org/repo", nil)
		require.NoError(t, err)
		release := make(chan struct{})
		s.verify = func(enclave string) (*VerifiedDocumentV3, error) {
			if enclave == "b.example" {
				<-release
			}
			return testState(time.Now().Add(time.Hour), enclave), nil
		}
		_, err = s.Verify()
		require.NoError(t, err)
		finished := make(chan error, 1)
		go func() { _, err := s.selectRouter(context.Background(), nil); finished <- err }()
		synctest.Wait()
		_, err = s.Verify()
		require.NoError(t, err)
		next = "c.example"
		_, err = s.selectRouter(context.Background(), nil)
		require.NoError(t, err)
		close(release)
		require.NoError(t, <-finished)
		require.Equal(t, "c.example", s.Enclave())
		require.Equal(t, "c.example", s.Verification().EnclaveHost)
		require.True(t, s.enclaves["b.example"].state.valid())
	})
}
