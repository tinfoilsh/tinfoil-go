package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/verifier/envelope"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testState(deadline time.Time, key string) *VerifiedDocumentV3 {
	return &VerifiedDocumentV3{
		CodeTag: key, FreshnessExpiresAt: deadline,
		CryptoMaterial: []envelope.CryptoMaterialItem{
			{ID: envelope.CryptoMaterialIDTLS, Format: envelope.KeySPKIFPSHA256V1Format, Data: key},
			{ID: envelope.CryptoMaterialIDHPKE, Format: envelope.KeyX25519HPKEV1Format, Data: key},
		},
	}
}

func testResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}
}

func TestTransportExpirationAndUnchangedWitness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		witnessedAt := time.Now()
		var verifications, requests int
		s, err := NewSecureClient("enclave.example", "org/repo", &VerificationOptions{FreshnessMaxAge: time.Minute})
		require.NoError(t, err)
		deadline := witnessedAt.Add(time.Minute)
		s.verify = func() (*VerifiedDocumentV3, error) {
			verifications++
			return testState(freshnessExpiration(witnessedAt, witnessedAt.Add(time.Hour), s.options.FreshnessMaxAge), "key"), nil
		}
		transport, err := s.NewTransport(func(*VerifiedDocumentV3) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests++
				return testResponse(), nil
			}), nil
		}, nil)
		require.NoError(t, err)
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		time.Sleep(time.Minute - time.Nanosecond)
		_, err = transport.RoundTrip(req)
		require.NoError(t, err)
		time.Sleep(time.Nanosecond)
		body, writer := io.Pipe()
		defer writer.Close()
		req, _ = http.NewRequest(http.MethodPost, "https://enclave.example", body)
		_, err = transport.RoundTrip(req)
		require.ErrorIs(t, err, ErrFreshnessExpired)
		_, err = writer.Write([]byte("must not send"))
		require.ErrorIs(t, err, io.ErrClosedPipe, "admission failure must close the request body")
		require.Equal(t, 1, requests, "expired keys must never authorize an application request")
		require.Equal(t, 2, verifications)
		require.Equal(t, deadline, s.state.FreshnessExpiresAt)
	})
}

func TestRefreshCoalescesRequestsAndExplicitVerify(t *testing.T) {
	for _, refreshErr := range []error{nil, errors.New("verification failed")} {
		t.Run("error="+errorString(refreshErr), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var attempts, requests atomic.Int32
				s := &SecureClient{state: testState(time.Now().Add(time.Minute), "old")}
				s.verify = func() (*VerifiedDocumentV3, error) {
					attempts.Add(1)
					<-release
					return testState(time.Now().Add(time.Hour), "new"), refreshErr
				}
				transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
					return roundTripFunc(func(*http.Request) (*http.Response, error) {
						requests.Add(1)
						if verified.CryptoMaterial[0].Data != "new" {
							return nil, errors.New("used old key")
						}
						return testResponse(), nil
					}), nil
				}, nil)
				require.NoError(t, err)
				time.Sleep(time.Minute)
				results := make(chan error, 33)
				for range 32 {
					go func() {
						req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
						_, err := transport.RoundTrip(req)
						results <- err
					}()
				}
				go func() { _, err := s.Verify(); results <- err }()
				synctest.Wait()
				require.EqualValues(t, 1, attempts.Load())
				close(release)
				for range 33 {
					require.ErrorIs(t, <-results, refreshErr)
				}
				if refreshErr != nil {
					require.Zero(t, requests.Load())
				} else {
					require.EqualValues(t, 32, requests.Load())
				}
			})
		})
	}
}

func errorString(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}

func TestRefreshWaitersCancelIndependentlyWithoutVerificationTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		s := &SecureClient{verify: func() (*VerifiedDocumentV3, error) {
			<-release
			return testState(time.Now().Add(time.Hour), "key"), nil
		}}
		ctx, cancel := context.WithCancel(context.Background())
		canceled, waiting := make(chan error, 1), make(chan error, 1)
		go func() { _, err := s.verifiedState(ctx, nil, false); canceled <- err }()
		go func() { _, err := s.Verify(); waiting <- err }()
		synctest.Wait()
		cancel()
		require.ErrorIs(t, <-canceled, context.Canceled)
		time.Sleep(time.Minute)
		select {
		case <-waiting:
			t.Fatal("shared verification must survive caller cancellation and has no SDK timeout")
		default:
		}
		close(release)
		require.NoError(t, <-waiting)
		require.NotNil(t, s.Verification())
	})
}

func TestVerificationFetchStillTimesOut(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	synctest.Test(t, func(t *testing.T) {
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})}
		start := time.Now()
		client, err := NewSecureClient("enclave.example", "org/repo", nil)
		require.NoError(t, err)
		_, err = client.Verify()
		require.ErrorIs(t, err, context.DeadlineExceeded)
		var fetch *FetchError
		require.ErrorAs(t, err, &fetch)
		require.True(t, strings.HasPrefix(err.Error(), "fetch error: "), "gomobile prefix contract")
		require.Equal(t, 30*time.Second, time.Since(start))
	})
}

func TestPreviouslyReturnedTransportsUseExplicitVerification(t *testing.T) {
	var attempts int
	s := &SecureClient{verify: func() (*VerifiedDocumentV3, error) {
		attempts++
		key := "old"
		if attempts > 1 {
			key = "new"
		}
		return testState(time.Now().Add(time.Hour), key), nil
	}}
	build := func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := testResponse()
			resp.Header.Set("Key", verified.CryptoMaterial[1].Data)
			return resp, nil
		}), nil
	}
	first, err := s.NewTransport(build, nil)
	require.NoError(t, err)
	second, err := s.NewTransport(build, nil)
	require.NoError(t, err)
	verified, err := s.Verify()
	require.NoError(t, err)
	verified.CryptoMaterial[1].Data = "caller mutation"
	for _, transport := range []http.RoundTripper{first, second} {
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, "new", resp.Header.Get("Key"))
	}
	require.Equal(t, "new", s.Verification().CryptoMaterial[1].Data)
	require.Equal(t, "new", s.Verification().CodeTag)
	require.Equal(t, 2, attempts)
}

func TestKeyRotationRetriesShareRefresh(t *testing.T) {
	for _, mode := range []struct {
		name    string
		keyErr  error
		matches func(error) bool
	}{
		{"TLS", ErrCertMismatch, isCertificateError},
		{"EHBP", ehbpidentity.NewKeyConfigError(errors.New("rotated")), ehbpidentity.IsKeyConfigError},
	} {
		t.Run(mode.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var attempts, sends atomic.Int32
				s := &SecureClient{state: testState(time.Now().Add(time.Hour), "old")}
				s.verify = func() (*VerifiedDocumentV3, error) {
					attempts.Add(1)
					<-release
					return testState(time.Now().Add(time.Hour), "new"), nil
				}
				transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
					return roundTripFunc(func(req *http.Request) (*http.Response, error) {
						defer req.Body.Close()
						body, err := io.ReadAll(req.Body)
						if err != nil || string(body) != "payload" {
							return nil, errors.New("body was not replayed")
						}
						sends.Add(1)
						if verified.CryptoMaterial[1].Data == "old" {
							return nil, mode.keyErr
						}
						return testResponse(), nil
					}), nil
				}, mode.matches)
				require.NoError(t, err)
				results := make(chan error, 17)
				for range 16 {
					go func() {
						req, _ := http.NewRequest(http.MethodPost, "https://enclave.example", bytes.NewBufferString("payload"))
						_, err := transport.RoundTrip(req)
						results <- err
					}()
				}
				go func() { _, err := s.Verify(); results <- err }()
				synctest.Wait()
				require.EqualValues(t, 1, attempts.Load())
				close(release)
				for range 17 {
					require.NoError(t, <-results)
				}
				require.EqualValues(t, 32, sends.Load())
				require.EqualValues(t, 1, attempts.Load())
			})
		})
	}
}

func TestKeyRotationRetryLimits(t *testing.T) {
	failed := errors.New("verification failed")
	for _, tc := range []struct {
		name                 string
		keyError, replayable bool
		refreshErr           error
		sends, refreshes     int
	}{
		{"other error", false, true, nil, 1, 0},
		{"unreplayable body", true, false, nil, 1, 0},
		{"retry only once", true, true, nil, 2, 1},
		{"refresh failure", true, true, failed, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sends, refreshes int
			original := errors.New("connection refused")
			if tc.keyError {
				original = ErrCertMismatch
			}
			s := &SecureClient{state: testState(time.Now().Add(time.Hour), "old"), verify: func() (*VerifiedDocumentV3, error) {
				refreshes++
				return testState(time.Now().Add(time.Hour), "new"), tc.refreshErr
			}}
			transport, err := s.NewTransport(func(*VerifiedDocumentV3) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					req.Body.Close()
					sends++
					return nil, original
				}), nil
			}, isCertificateError)
			require.NoError(t, err)
			req, _ := http.NewRequest(http.MethodPost, "https://enclave.example", bytes.NewBufferString("payload"))
			if !tc.replayable {
				req.GetBody = nil
			}
			_, err = transport.RoundTrip(req)
			require.ErrorIs(t, err, original)
			if tc.refreshErr != nil {
				require.ErrorIs(t, err, tc.refreshErr)
			}
			require.Equal(t, tc.sends, sends)
			require.Equal(t, tc.refreshes, refreshes)
		})
	}
}

func TestExpirationDoesNotInterruptStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deadline := time.Now().Add(time.Minute)
		s := &SecureClient{state: testState(deadline, "key"), verify: func() (*VerifiedDocumentV3, error) {
			return testState(deadline, "key"), nil
		}}
		reader, writer := io.Pipe()
		transport, err := s.NewTransport(func(*VerifiedDocumentV3) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				resp := testResponse()
				resp.Body = reader
				return resp, nil
			}), nil
		}, nil)
		require.NoError(t, err)
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		time.Sleep(time.Minute)
		_, err = transport.RoundTrip(req)
		require.ErrorIs(t, err, ErrFreshnessExpired)
		go func() { defer writer.Close(); _, _ = io.WriteString(writer, "still streaming") }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "still streaming", string(body))
	})
}

func TestRedirectChecksExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deadline := time.Now().Add(time.Minute)
		var sends int
		s := &SecureClient{state: testState(deadline, "key"), verify: func() (*VerifiedDocumentV3, error) {
			return testState(deadline, "key"), nil
		}}
		transport, err := s.NewTransport(func(*VerifiedDocumentV3) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				sends++
				resp := testResponse()
				resp.StatusCode = http.StatusFound
				resp.Header.Set("Location", "/redirected")
				return resp, nil
			}), nil
		}, nil)
		require.NoError(t, err)
		hc := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			time.Sleep(time.Minute)
			return nil
		}}
		_, err = hc.Get("https://enclave.example")
		require.ErrorIs(t, err, ErrFreshnessExpired)
		require.Equal(t, 1, sends)
	})
}

func TestHTTPClientChecksExpirationOnReusedTLSConnections(t *testing.T) {
	for _, useProxy := range []bool{false, true} {
		name := "direct"
		if useProxy {
			name = "CONNECT"
		}
		t.Run(name, func(t *testing.T) {
			var sends atomic.Int32
			target := newECDSATLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sends.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			key, err := CertPubkeyFP(target.Certificate())
			require.NoError(t, err)
			s := &SecureClient{state: testState(time.Now().Add(time.Hour), key), verify: func() (*VerifiedDocumentV3, error) {
				return testState(time.Now().Add(-time.Second), key), nil
			}}
			hc, err := s.HTTPClient()
			require.NoError(t, err)
			defer hc.CloseIdleConnections()
			base := hc.Transport.(*refreshingTransport).transport.(*TLSBoundRoundTripper).getTransport()
			base.Proxy = nil
			base.TLSClientConfig.RootCAs = roots
			if useProxy {
				proxy := newConnectProxy()
				defer proxy.Close()
				proxyURL, err := url.Parse(proxy.URL)
				require.NoError(t, err)
				base.Proxy = http.ProxyURL(proxyURL)
			}
			for i := range 2 {
				var reused bool
				req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}))
				resp, err := hc.Do(req)
				require.NoError(t, err)
				resp.Body.Close()
				require.Equal(t, i == 1, reused)
			}
			// Publish an expired snapshot without modifying the immutable snapshot
			// held by the already-returned HTTP client and its open connection.
			s.stateMu.Lock()
			s.state = testState(time.Now().Add(-time.Second), key)
			s.stateMu.Unlock()
			_, err = hc.Get(target.URL)
			require.ErrorIs(t, err, ErrFreshnessExpired)
			require.EqualValues(t, 2, sends.Load())
		})
	}
}

func TestIsCertificateError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "generic error",
			err:      errors.New("some random error"),
			expected: false,
		},
		{
			name:     "ErrNoTLS",
			err:      ErrNoTLS,
			expected: false,
		},
		{
			name:     "wrapped ErrNoTLS",
			err:      errors.Join(errors.New("connection failed"), ErrNoTLS),
			expected: false,
		},
		{
			name:     "ErrCertMismatch",
			err:      ErrCertMismatch,
			expected: true,
		},
		{
			name:     "wrapped ErrCertMismatch",
			err:      errors.Join(errors.New("request failed"), ErrCertMismatch),
			expected: true,
		},
		{
			name:     "x509.CertificateInvalidError",
			err:      x509.CertificateInvalidError{Reason: x509.Expired},
			expected: true,
		},
		{
			name:     "x509.UnknownAuthorityError",
			err:      x509.UnknownAuthorityError{},
			expected: true,
		},
		{
			name:     "x509.HostnameError",
			err:      x509.HostnameError{Host: "example.com"},
			expected: true,
		},
		{
			name:     "tls.CertificateVerificationError",
			err:      &tls.CertificateVerificationError{Err: errors.New("verification failed")},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isCertificateError(tt.err)
			require.Equal(t, tt.expected, result)
		})
	}
}
