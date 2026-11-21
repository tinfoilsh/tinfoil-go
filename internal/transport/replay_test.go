package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

type testKeyRejection struct{ error }

func (e testKeyRejection) KeyRejected() bool { return true }
func (e testKeyRejection) Unwrap() error     { return e.error }

func TestRequestRecovery(t *testing.T) {
	first, last := errors.New("rejected key"), errors.New("second failure")
	for _, tc := range []struct {
		name        string
		first, last error
		replayable  bool
		cancel      bool
		attempts    int
	}{
		{"success", testKeyRejection{first}, nil, true, false, 2},
		{"second rejection", testKeyRejection{first}, testKeyRejection{last}, true, false, 2},
		{"refresh failure", testKeyRejection{first}, errs.Network(last), true, false, 2},
		{"network failure", first, nil, true, false, 1},
		{"unreplayable", testKeyRejection{first}, nil, false, false, 1},
		{"canceled", testKeyRejection{first}, nil, true, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var attempts int
			transport := WithReplay(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				attempts++
				body, err := io.ReadAll(req.Body)
				req.Body.Close()
				require.NoError(t, err)
				require.Equal(t, "payload", string(body))
				require.Equal(t, "secret", req.Header.Get("Authorization"))
				if attempts == 1 {
					if tc.cancel {
						cancel()
					}
					return nil, tc.first
				}
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, tc.last
			}), IsKeyRejection)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://enclave.example/path?q=1", strings.NewReader("payload"))
			require.NoError(t, err)
			req.Header.Set("Authorization", "secret")
			if !tc.replayable {
				req.GetBody = nil
			}
			resp, err := transport.RoundTrip(req)
			require.Equal(t, tc.attempts, attempts)
			if tc.attempts == 2 && tc.last == nil {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				resp.Body.Close()
			} else {
				// Each failure reports one error, as net/http.Transport does.
				require.Nil(t, resp)
				switch {
				case tc.cancel:
					require.Equal(t, context.Canceled, err, "the context's error, unwrapped")
					testutil.RequireCategory(t, err, nil)
				case !tc.replayable:
					testutil.RequireCategory(t, err, errs.ErrNetwork)
					require.NotErrorIs(t, err, first)
					require.ErrorContains(t, err, first.Error())
				case tc.last != nil:
					require.ErrorIs(t, err, last)
					require.NotErrorIs(t, err, first)
				default:
					require.Equal(t, first, err)
				}
			}
		})
	}
}

func TestRequestClientClosesIdleConnections(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	hc := server.Client()
	hc.Transport = WithReplay(hc.Transport, IsKeyRejection)
	defer hc.CloseIdleConnections()
	for i, expectedReuse := range []bool{false, true, false} {
		if i == 2 {
			hc.CloseIdleConnections()
		}
		var reused bool
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		require.NoError(t, err)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
		}))
		resp, err := hc.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, expectedReuse, reused)
	}
}

func TestRequestRecoveryDiscardsErrorResponses(t *testing.T) {
	for _, replayable := range []bool{false, true} {
		var bodies []*closeCountingBody
		cause := errors.New("rejected")
		transport := WithReplay(roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req.Body.Close()
			body := &closeCountingBody{Reader: strings.NewReader("failure")}
			bodies = append(bodies, body)
			return &http.Response{StatusCode: http.StatusBadRequest, Body: body}, testKeyRejection{cause}
		}), IsKeyRejection)
		req, err := http.NewRequest(http.MethodPost, "https://enclave.example", strings.NewReader("payload"))
		require.NoError(t, err)
		if !replayable {
			req.GetBody = nil
		}
		resp, err := transport.RoundTrip(req)
		require.Nil(t, resp)
		require.ErrorContains(t, err, cause.Error())
		for _, body := range bodies {
			require.Equal(t, 1, body.closes)
		}
	}
}

// closeCountingBody counts the reads and closes of a response body.
type closeCountingBody struct {
	io.Reader
	reads, closes int
}

func (b *closeCountingBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

func (b *closeCountingBody) Close() error {
	b.closes++
	return nil
}

func TestReplayAsksOnlyAboutErrors(t *testing.T) {
	transport := WithReplay(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return newResponse(http.StatusOK, "ok"), nil
	}), func(err error) bool {
		t.Errorf("asked whether to retry %v", err)
		return false
	})
	req, err := http.NewRequest(http.MethodGet, "https://enclave.example", nil)
	require.NoError(t, err)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
}

// rejectingModes are the transport modes, each with a round tripper that
// rejects every request the way that mode reports a rotated key.
var rejectingModes = []struct {
	name      string
	rejection error
	mode      testMode
}{
	{"TLS", errCertMismatch, testMode(func(*verify.Verification) (http.RoundTripper, error) {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			closeRequestBody(req)
			// As TLSBoundRoundTripper reports a certificate error.
			return nil, &peerLacksKeyError{errs.WrapAttestation(errCertMismatch)}
		}), nil
	})},
	{"EHBP", ehbpKeyConfigError, testMode(func(*verify.Verification) (http.RoundTripper, error) {
		return &ehbpRoundTripper{sealing: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			closeRequestBody(req)
			return nil, ehbpKeyConfigError
		})}, nil
	})},
}

var ehbpKeyConfigError = ehbpidentity.NewKeyConfigError(errors.New("rotated"))

func TestUnreplayableKeyRejectionIsANetworkError(t *testing.T) {
	bodyErr := errors.New("body is gone")
	classifiedCause := errors.New("classified body failure")
	classifiedBodyErr := errs.Attestation(classifiedCause)
	for _, mode := range rejectingModes {
		for _, body := range []struct {
			name    string
			getBody func() (io.ReadCloser, error)
			// reached is whether errors.Is reaches the error that GetBody
			// returned.
			reached bool
			bodyErr error
		}{
			{"no GetBody", nil, false, nil},
			{"GetBody fails", func() (io.ReadCloser, error) { return nil, bodyErr }, true, bodyErr},
			// A GetBody error that has a category of its own is reached
			// without it, so that the result keeps one category.
			{"GetBody fails with a category", func() (io.ReadCloser, error) { return nil, classifiedBodyErr }, false, classifiedBodyErr},
		} {
			t.Run(mode.name+"/"+body.name, func(t *testing.T) {
				var refreshes int
				tr := newTestTransport(t, testState(time.Now().Add(time.Hour), "old"), func() (*verify.Verification, error) {
					refreshes++
					return testState(time.Now().Add(time.Hour), "new"), nil
				}, mode.mode)
				req, err := http.NewRequest(http.MethodPost, "https://enclave.example", strings.NewReader("payload"))
				require.NoError(t, err)
				req.GetBody = body.getBody
				resp, err := WithReplay(tr, IsKeyRejection).RoundTrip(req)
				require.Nil(t, resp)
				testutil.RequireCategory(t, err, errs.ErrNetwork)
				require.NotErrorIs(t, err, mode.rejection, "the rejection is only in the message")
				require.ErrorContains(t, err, mode.rejection.Error())
				require.ErrorContains(t, err, "the request body can't be replayed")
				require.True(t, IsKeyRejection(err))
				if body.bodyErr != nil {
					require.ErrorContains(t, err, body.bodyErr.Error())
					if body.reached {
						require.ErrorIs(t, err, body.bodyErr)
					} else {
						require.NotErrorIs(t, err, body.bodyErr)
						require.ErrorIs(t, err, classifiedCause, "its cause is still reached")
					}
				}
				require.False(t, currentValid(tr), "the rejection still invalidates the verification")
				require.Zero(t, refreshes)
			})
		}
	}
}

func TestReplayReportsOnlyTheReplaysError(t *testing.T) {
	cause := errors.New("replay failed")
	for _, tc := range []struct {
		name     string
		err      error
		category error
	}{
		{"configuration", errs.Configuration(cause), errs.ErrConfiguration},
		{"network", errs.Network(cause), errs.ErrNetwork},
		{"attestation", errs.Attestation(cause), errs.ErrAttestation},
		{"uncategorized", cause, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts int
			transport := WithReplay(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				closeRequestBody(req)
				attempts++
				if attempts == 1 {
					// A TLS key rejection, which is an attestation error.
					return nil, &keyRejectionError{&peerLacksKeyError{errs.WrapAttestation(errCertMismatch)}}
				}
				return nil, tc.err
			}), IsKeyRejection)
			req, err := http.NewRequest(http.MethodPost, "https://enclave.example", strings.NewReader("payload"))
			require.NoError(t, err)
			_, err = transport.RoundTrip(req)
			require.Equal(t, 2, attempts)
			require.Same(t, tc.err, err)
			testutil.RequireCategory(t, err, tc.category)
		})
	}
}

func TestReplayReportsOnlyTheCallersCancellation(t *testing.T) {
	for _, mode := range rejectingModes {
		t.Run(mode.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var refreshes int
			tr := newTestTransport(t, testState(time.Now().Add(time.Hour), "old"), func() (*verify.Verification, error) {
				refreshes++
				return testState(time.Now().Add(time.Hour), "new"), nil
			}, testMode(func(v *verify.Verification) (http.RoundTripper, error) {
				rt, err := mode.mode(v)
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					cancel()
					return rt.RoundTrip(req)
				}), err
			}))
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://enclave.example", strings.NewReader("payload"))
			require.NoError(t, err)
			_, err = WithReplay(tr, IsKeyRejection).RoundTrip(req)
			require.Equal(t, context.Canceled, err, "the context's error, unwrapped")
			testutil.RequireCategory(t, err, nil)
			require.Zero(t, refreshes)
		})
	}
}
