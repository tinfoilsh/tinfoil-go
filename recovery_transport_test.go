package tinfoil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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
		{"refresh failure", testKeyRejection{first}, &FetchError{Err: last}, true, false, 2},
		{"network failure", first, nil, true, false, 1},
		{"unreplayable", testKeyRejection{first}, nil, false, false, 1},
		{"canceled", testKeyRejection{first}, nil, true, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var attempts int
			transport := &recoveryTransport{transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
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
			})}
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
				require.Nil(t, resp)
				require.ErrorIs(t, err, first)
				if tc.last != nil {
					require.ErrorIs(t, err, last)
				}
				if tc.cancel {
					require.ErrorIs(t, err, context.Canceled)
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
	host := strings.TrimPrefix(server.URL, "https://")
	hc, err := boundHTTPClient(server.Client(), host, "", "cache-secret")
	require.NoError(t, err)
	hc.Transport = &recoveryTransport{transport: hc.Transport}
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
		var bodies []*sealTestBody
		cause := errors.New("rejected")
		transport := &recoveryTransport{transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			req.Body.Close()
			body := &sealTestBody{Reader: strings.NewReader("failure")}
			bodies = append(bodies, body)
			return &http.Response{StatusCode: http.StatusBadRequest, Body: body}, testKeyRejection{cause}
		})}
		req, err := http.NewRequest(http.MethodPost, "https://enclave.example", strings.NewReader("payload"))
		require.NoError(t, err)
		if !replayable {
			req.GetBody = nil
		}
		resp, err := transport.RoundTrip(req)
		require.Nil(t, resp)
		require.ErrorIs(t, err, cause)
		for _, body := range bodies {
			require.Equal(t, 1, body.closes)
		}
	}
}
