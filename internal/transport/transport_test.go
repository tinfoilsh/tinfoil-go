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

// newTestTransport is a Transport over the transport build makes for each
// verification, with an optional key-rejection test and no request check.
func newTestTransport(h *enclave.Handle, build func(*verify.Verification) (http.RoundTripper, error), keyRejected func(error) bool) (*Transport, error) {
	if keyRejected == nil {
		keyRejected = func(error) bool { return false }
	}
	return &Transport{handle: h, build: build, keyRejected: keyRejected, check: func(*http.Request) error { return nil }}, nil
}

// verifyNow verifies h again and returns the caller's copy.
func verifyNow(h *enclave.Handle) (*verify.Verification, error) {
	state, err := h.Reverify(context.Background())
	if err != nil {
		return nil, err
	}
	return state.Verification(), nil
}

// current returns a copy of h's last verification, or nil.
func current(h *enclave.Handle) *verify.Verification {
	if state := h.Current(); state != nil {
		return state.Verification()
	}
	return nil
}

// tlsClient is an HTTP client pinned through h.
func tlsClient(h *enclave.Handle) *http.Client {
	return &http.Client{Transport: TLS(h)}
}

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
		s := enclave.NewTestHandle("enclave.example", nil, func() (*verify.Verification, error) {
			verifications++
			return testState(deadline, "key"), nil
		})
		transport, err := newTestTransport(s, func(*verify.Verification) (http.RoundTripper, error) {
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
		require.ErrorIs(t, err, enclave.ErrFreshnessExpired)
		_, err = writer.Write([]byte("must not send"))
		require.ErrorIs(t, err, io.ErrClosedPipe, "admission failure must close the request body")
		require.Equal(t, 1, requests, "expired keys must never authorize an application request")
		require.Equal(t, 3, verifications)
		require.Equal(t, deadline, current(s).FreshnessExpiresAt())
	})
}

func TestRefreshCoalescesRequestsAndExplicitVerify(t *testing.T) {
	for _, refreshErr := range []error{nil, errors.New("verification failed")} {
		t.Run("error="+errorString(refreshErr), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var attempts, requests atomic.Int32
				s := enclave.NewTestHandle("enclave.example", testState(time.Now().Add(time.Minute), "old"), func() (*verify.Verification, error) {
					attempts.Add(1)
					<-release
					return testState(time.Now().Add(time.Hour), "new"), refreshErr
				})
				transport, err := newTestTransport(s, func(verified *verify.Verification) (http.RoundTripper, error) {
					return roundTripFunc(func(*http.Request) (*http.Response, error) {
						requests.Add(1)
						if verified.CryptoMaterial()[0].Data != "new" {
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
				go func() { _, err := verifyNow(s); results <- err }()
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

func TestPreviouslyReturnedTransportsUseExplicitVerification(t *testing.T) {
	var attempts int
	s := enclave.NewTestHandle("enclave.example", nil, func() (*verify.Verification, error) {
		attempts++
		key := "old"
		if attempts > 1 {
			key = "new"
		}
		return testState(time.Now().Add(time.Hour), key), nil
	})
	build := func(verified *verify.Verification) (http.RoundTripper, error) {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := testResponse()
			resp.Header.Set("Key", verified.CryptoMaterial()[1].Data)
			return resp, nil
		}), nil
	}
	first, err := newTestTransport(s, build, nil)
	require.NoError(t, err)
	_, err = first.EnsureVerified(context.Background())
	require.NoError(t, err)
	second, err := newTestTransport(s, build, nil)
	require.NoError(t, err)
	verified, err := verifyNow(s)
	require.NoError(t, err)
	verified.CryptoMaterial()[1].Data = "caller mutation"
	for _, transport := range []http.RoundTripper{first, second} {
		req, _ := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, "new", resp.Header.Get("Key"))
	}
	require.Equal(t, "new", current(s).CryptoMaterial()[1].Data)
	require.Equal(t, "new", current(s).CodeTag())
	require.Equal(t, 2, attempts)
}

func TestKeyRejectionInvalidatesWithoutReplay(t *testing.T) {
	for _, mode := range []struct {
		name    string
		err     error
		matches func(error) bool
	}{
		{"TLS", errCertMismatch, isCertificateError},
		{"EHBP", ehbpidentity.NewKeyConfigError(errors.New("rotated")), ehbpidentity.IsKeyConfigError},
		{"network", errors.New("connection refused"), isCertificateError},
	} {
		t.Run(mode.name, func(t *testing.T) {
			var sends, refreshes int
			refresh := func() (*verify.Verification, error) {
				refreshes++
				return testState(time.Now().Add(time.Hour), "new"), nil
			}
			fetch := refresh
			s := enclave.NewTestHandle("enclave.example", testState(time.Now().Add(time.Hour), "old"), func() (*verify.Verification, error) { return fetch() })
			transport, err := newTestTransport(s, func(*verify.Verification) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					req.Body.Close()
					sends++
					return nil, mode.err
				}), nil
			}, mode.matches)
			require.NoError(t, err)
			req, _ := http.NewRequest(http.MethodPost, "https://enclave.example", bytes.NewBufferString("payload"))
			req.GetBody = nil
			_, err = transport.RoundTrip(req)
			require.ErrorIs(t, err, mode.err)
			require.Equal(t, mode.matches(mode.err), IsKeyRejection(err))
			rejected := !s.Valid(s.Current())
			require.Equal(t, mode.matches(mode.err), rejected)
			require.Equal(t, "old", current(s).CodeTag())
			require.Equal(t, 1, sends)
			require.Zero(t, refreshes)
			if rejected {
				failure := errors.New("refresh failed")
				fetch = func() (*verify.Verification, error) { return nil, failure }
				req, _ = http.NewRequest(http.MethodGet, "https://enclave.example", nil)
				_, err = transport.RoundTrip(req)
				require.ErrorIs(t, err, failure)
				require.False(t, s.Valid(s.Current()))
				require.Equal(t, "old", current(s).CodeTag())
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
		s := enclave.NewTestHandle("enclave.example", testState(deadline, "key"), func() (*verify.Verification, error) {
			return testState(deadline, "key"), nil
		})
		reader, writer := io.Pipe()
		transport, err := newTestTransport(s, func(*verify.Verification) (http.RoundTripper, error) {
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
		s := enclave.NewTestHandle("enclave.example", testState(deadline, "key"), func() (*verify.Verification, error) {
			return testState(deadline, "key"), nil
		})
		transport, err := newTestTransport(s, func(*verify.Verification) (http.RoundTripper, error) {
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
			s := enclave.NewTestHandle("enclave.example", testState(time.Now().Add(time.Hour), key), func() (*verify.Verification, error) {
				return testState(time.Now().Add(-time.Second), key), nil
			})
			hc := tlsClient(s)
			defer hc.CloseIdleConnections()
			_, err = hc.Transport.(*Transport).EnsureVerified(context.Background())
			require.NoError(t, err)
			base := hc.Transport.(*Transport).inner.(*TLSBoundRoundTripper).transport
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
			s.Invalidate(s.Current())
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
// one the handle hands out is the caller's own.
func TestCallersCannotReplaceCachedVerification(t *testing.T) {
	s := enclave.NewTestHandle("enclave.example", nil, func() (*verify.Verification, error) {
		return testState(time.Now().Add(time.Hour), "key"), nil
	})
	verified, err := verifyNow(s)
	require.NoError(t, err)
	*verified = *testState(time.Now().Add(time.Hour), "other")
	*current(s) = *testState(time.Now().Add(time.Hour), "other")
	transport, err := newTestTransport(s, func(v *verify.Verification) (http.RoundTripper, error) {
		*v = *testState(time.Now().Add(time.Hour), "other")
		return roundTripFunc(func(*http.Request) (*http.Response, error) { return testResponse(), nil }), nil
	}, nil)
	require.NoError(t, err)
	_, err = transport.EnsureVerified(context.Background())
	require.NoError(t, err)

	require.Equal(t, "key", current(s).CodeTag())
	fp, ok := current(s).TLSPublicKeyFP()
	require.True(t, ok)
	require.Equal(t, "key", fp)
}
