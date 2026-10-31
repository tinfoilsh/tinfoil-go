package transport

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
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// testMode creates the round tripper build makes for each verification and
// validates no requests.
type testMode func(*verify.Verification) (http.RoundTripper, error)

func (testMode) validateRequest(*http.Request) error                                 { return nil }
func (m testMode) newRoundTripper(v *verify.Verification) (http.RoundTripper, error) { return m(v) }

// newTestTransport returns a Transport in mode m for enclave.example that
// starts from initial, unless it is nil, and verifies by calling fetch.
func newTestTransport(t *testing.T, initial *verify.Verification, fetch func() (*verify.Verification, error), m mode) *Transport {
	t.Helper()
	tr := &Transport{enclave: enclave.NewForTest("enclave.example", fetch), mode: m}
	if initial != nil {
		s, err := tr.newState(initial)
		require.NoError(t, err)
		tr.current = s
	}
	return tr
}

// currentValid reports whether tr's current verification can authorize
// requests.
func currentValid(tr *Transport) bool {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return tr.current != nil && tr.current.valid()
}

// invalidateCurrent rejects tr's current verification, as a key rejection
// would.
func invalidateCurrent(tr *Transport) {
	tr.mu.RLock()
	s := tr.current
	tr.mu.RUnlock()
	tr.invalidate(s)
}

// sendOK is a test mode whose round trippers answer every request.
var sendOK = testMode(func(*verify.Verification) (http.RoundTripper, error) {
	return roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil }), nil
})

func testState(deadline time.Time, key string) *verify.Verification {
	return verifytest.New(verifytest.Fields{
		CodeTag: key, FreshnessExpiresAt: deadline,
		CryptoMaterial: []document.CryptoMaterialItem{
			{ID: document.CryptoMaterialIDTLS, Format: document.KeySPKIFPSHA256V1Format, Data: key},
			{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: key},
		},
	})
}

func testResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}
}

func TestTransportExpirationAndUnchangedWitness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		witnessedAt := time.Now()
		var verifications, requests int
		deadline := witnessedAt.Add(time.Minute)
		transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
			verifications++
			return testState(deadline, "key"), nil
		}, testMode(func(*verify.Verification) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				requests++
				return testResponse(), nil
			}), nil
		}))
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		time.Sleep(time.Minute - time.Nanosecond)
		_, err := transport.RoundTrip(req)
		require.NoError(t, err)
		time.Sleep(time.Nanosecond)
		body, writer := io.Pipe()
		defer writer.Close()
		req, _ = http.NewRequest(http.MethodPost, "https://enclave.example", body)
		_, err = transport.RoundTrip(req)
		require.ErrorIs(t, err, enclave.ErrFreshnessExpired)
		_, err = writer.Write([]byte("must not send"))
		require.ErrorIs(t, err, io.ErrClosedPipe, "admission failure must close the request body")
		require.Equal(t, 1, requests, "expired keys must never authorize an application request")
		require.Equal(t, 3, verifications)
		require.Equal(t, deadline, transport.Current().FreshnessExpiresAt())
	})
}

func TestRefreshCoalescesRequestsAndExplicitVerify(t *testing.T) {
	for _, refreshErr := range []error{nil, errors.New("verification failed")} {
		t.Run("error="+errorString(refreshErr), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var attempts, requests atomic.Int32
				transport := newTestTransport(t, testState(time.Now().Add(time.Minute), "old"), func() (*verify.Verification, error) {
					attempts.Add(1)
					<-release
					return testState(time.Now().Add(time.Hour), "new"), refreshErr
				}, testMode(func(verified *verify.Verification) (http.RoundTripper, error) {
					return roundTripFunc(func(*http.Request) (*http.Response, error) {
						requests.Add(1)
						if verified.CryptoMaterial()[0].Data != "new" {
							return nil, errors.New("used old key")
						}
						return testResponse(), nil
					}), nil
				}))
				time.Sleep(time.Minute)
				results := make(chan error, 33)
				for range 32 {
					go func() {
						req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
						_, err := transport.RoundTrip(req)
						results <- err
					}()
				}
				go func() { _, err := transport.Reverify(context.Background()); results <- err }()
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

func TestRequestsUseExplicitVerification(t *testing.T) {
	var attempts int
	transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
		attempts++
		key := "old"
		if attempts > 1 {
			key = "new"
		}
		return testState(time.Now().Add(time.Hour), key), nil
	}, testMode(func(verified *verify.Verification) (http.RoundTripper, error) {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := testResponse()
			resp.Header.Set("Key", verified.CryptoMaterial()[1].Data)
			return resp, nil
		}), nil
	}))
	_, err := transport.EnsureVerified(context.Background())
	require.NoError(t, err)
	verified, err := transport.Reverify(context.Background())
	require.NoError(t, err)
	verified.CryptoMaterial()[1].Data = "caller mutation"
	req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, "new", resp.Header.Get("Key"))
	require.Equal(t, "new", transport.Current().CryptoMaterial()[1].Data)
	require.Equal(t, "new", transport.Current().CodeTag())
	require.Equal(t, 2, attempts)
}

func TestKeyRejectionInvalidatesWithoutReplay(t *testing.T) {
	for _, mode := range []struct {
		name     string
		err      error
		lacksKey bool
	}{
		{"TLS", errCertMismatch, true},
		{"EHBP", ehbpidentity.NewKeyConfigError(errors.New("rotated")), true},
		{"network", errors.New("connection refused"), false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var sends, refreshes int
			refresh := func() (*verify.Verification, error) {
				refreshes++
				return testState(time.Now().Add(time.Hour), "new"), nil
			}
			fetch := refresh
			transport := newTestTransport(t, testState(time.Now().Add(time.Hour), "old"), func() (*verify.Verification, error) { return fetch() }, testMode(func(*verify.Verification) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					req.Body.Close()
					sends++
					if mode.lacksKey {
						return nil, &peerLacksKeyError{mode.err}
					}
					return nil, mode.err
				}), nil
			}))
			req, _ := http.NewRequest(http.MethodPost, "https://enclave.example", bytes.NewBufferString("payload"))
			req.GetBody = nil
			_, err := transport.RoundTrip(req)
			require.ErrorIs(t, err, mode.err)
			require.Equal(t, mode.lacksKey, IsKeyRejection(err))
			rejected := !currentValid(transport)
			require.Equal(t, mode.lacksKey, rejected)
			require.Equal(t, "old", transport.Current().CodeTag())
			require.Equal(t, 1, sends)
			require.Zero(t, refreshes)
			if rejected {
				failure := errors.New("refresh failed")
				fetch = func() (*verify.Verification, error) { return nil, failure }
				req, _ = http.NewRequest(http.MethodGet, "https://enclave.example", nil)
				_, err = transport.RoundTrip(req)
				require.ErrorIs(t, err, failure)
				require.False(t, currentValid(transport))
				require.Equal(t, "old", transport.Current().CodeTag())
				require.Equal(t, 1, sends, "failed refresh must not authorize the rejected state")
				fetch = refresh
				req, _ = http.NewRequest(http.MethodPost, "https://enclave.example", bytes.NewBufferString("another request"))
				_, err = transport.RoundTrip(req)
				require.ErrorIs(t, err, mode.err)
				require.Equal(t, 1, refreshes, "a later request must establish fresh state")
			}
		})
	}
}

func TestExpirationDoesNotInterruptStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deadline := time.Now().Add(time.Minute)
		reader, writer := io.Pipe()
		transport := newTestTransport(t, testState(deadline, "key"), func() (*verify.Verification, error) {
			return testState(deadline, "key"), nil
		}, testMode(func(*verify.Verification) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				resp := testResponse()
				resp.Body = reader
				return resp, nil
			}), nil
		}))
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		time.Sleep(time.Minute)
		_, err = transport.RoundTrip(req)
		require.ErrorIs(t, err, enclave.ErrFreshnessExpired)
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
		transport := newTestTransport(t, testState(deadline, "key"), func() (*verify.Verification, error) {
			return testState(deadline, "key"), nil
		}, testMode(func(*verify.Verification) (http.RoundTripper, error) {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				sends++
				resp := testResponse()
				resp.StatusCode = http.StatusFound
				resp.Header.Set("Location", "/redirected")
				return resp, nil
			}), nil
		}))
		hc := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			time.Sleep(time.Minute)
			return nil
		}}
		_, err := hc.Get("https://enclave.example")
		require.ErrorIs(t, err, enclave.ErrFreshnessExpired)
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
			key, err := verify.CertPubkeyFP(target.Certificate())
			require.NoError(t, err)
			pinning := newTestTransport(t, testState(time.Now().Add(time.Hour), key), func() (*verify.Verification, error) {
				return testState(time.Now().Add(-time.Second), key), nil
			}, tlsMode{})
			hc := &http.Client{Transport: pinning}
			defer hc.CloseIdleConnections()
			base := pinning.current.roundTripper.(*TLSBoundRoundTripper).transport
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
			// Retire the state the open connection was admitted under; the
			// refresh finds only expired evidence.
			invalidateCurrent(pinning)
			_, err = hc.Get(target.URL)
			require.ErrorIs(t, err, enclave.ErrFreshnessExpired)
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
			name:     "errNoTLS",
			err:      errNoTLS,
			expected: false,
		},
		{
			name:     "wrapped errNoTLS",
			err:      errors.Join(errors.New("connection failed"), errNoTLS),
			expected: false,
		},
		{
			name:     "errCertMismatch",
			err:      errCertMismatch,
			expected: true,
		},
		{
			name:     "wrapped errCertMismatch",
			err:      errors.Join(errors.New("request failed"), errCertMismatch),
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

// Unexported fields do not stop a caller from replacing a whole Verification
// through a pointer, here with another valid one carrying other keys, so every
// one the transport hands out is the caller's own.
func TestCallersCannotReplaceCachedVerification(t *testing.T) {
	transport := newTestTransport(t, nil, func() (*verify.Verification, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	}, testMode(func(v *verify.Verification) (http.RoundTripper, error) {
		*v = *testState(time.Now().Add(time.Hour), "other")
		return roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil }), nil
	}))
	verified, err := transport.Reverify(context.Background())
	require.NoError(t, err)
	*verified = *testState(time.Now().Add(time.Hour), "other")
	*transport.Current() = *testState(time.Now().Add(time.Hour), "other")
	_, err = transport.EnsureVerified(context.Background())
	require.NoError(t, err)

	require.Equal(t, "key", transport.Current().CodeTag())
	fp, ok := transport.Current().TLSPublicKeyFP()
	require.True(t, ok)
	require.Equal(t, "key", fp)
}
