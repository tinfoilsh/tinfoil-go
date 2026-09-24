package tinfoil

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	sealTestModel   = "test-model"
	sealTestInitial = "initial.example"
)

func sealTestTransport(build func(host string) (http.RoundTripper, error)) *sealTransport {
	return &sealTransport{
		build: func(r replica) (http.RoundTripper, error) { return build(r.host) },
		catalog: func() Catalog {
			return Catalog{sealTestModel: {Repo: "tinfoilsh/test", Hosts: []string{sealTestInitial}}}
		},
	}
}

func sealMismatch(enclave string) *http.Response {
	resp := newResponse(http.StatusPreconditionFailed, "")
	resp.Header.Set(sealHeader, enclave)
	return resp
}

func TestSealRerouteIsPerRequest(t *testing.T) {
	verificationErr := errors.New("verification failed")
	var nextBuilds, initialHits int
	seal := sealTestTransport(func(host string) (http.RoundTripper, error) {
		if host != sealTestInitial {
			nextBuilds++
			if nextBuilds == 1 {
				return nil, verificationErr
			}
		}
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if host == sealTestInitial {
				initialHits++
				return sealMismatch("next.example"), nil
			}
			return newResponse(http.StatusNoContent, ""), nil
		}), nil
	})
	get := func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "https://gateway.example/reroute", nil)
		require.NoError(t, err)
		req.Header.Set(modelHeader, sealTestModel)
		return seal.RoundTrip(req)
	}
	_, err := get()
	require.ErrorIs(t, err, verificationErr)
	for range 2 {
		resp, err := get()
		require.NoError(t, err)
		resp.Body.Close()
	}
	require.Equal(t, 3, initialHits, "every request starts from its own pick, not the last reroute")
	require.Equal(t, 2, nextBuilds, "a failed verification is retried, a successful one is reused")
}

type sealTestBody struct {
	io.Reader
	reads, closes int
}

func (b *sealTestBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

func (b *sealTestBody) Close() error {
	b.closes++
	return nil
}

func TestSealUploadReplay(t *testing.T) {
	const payload = "upload contents"
	replayErr := errors.New("cannot reopen upload")
	for _, tc := range []struct {
		name      string
		getBody   bool
		replayErr error
	}{
		{name: "replays", getBody: true},
		{name: "no GetBody"},
		{name: "GetBody fails", getBody: true, replayErr: replayErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &sealTestBody{Reader: strings.NewReader(payload)}
			replayed := &sealTestBody{Reader: strings.NewReader(payload)}
			responseBody := &sealTestBody{Reader: strings.NewReader("")}
			var attempts int
			seal := sealTestTransport(func(host string) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					defer req.Body.Close()
					attempts++
					if host == sealTestInitial {
						require.Same(t, original, req.Body)
						require.Zero(t, original.reads, "headers must reach the transport before the upload is read")
						resp := sealMismatch("next.example")
						resp.Body = responseBody
						return resp, nil
					}
					require.Same(t, replayed, req.Body)
					body, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					require.Equal(t, payload, string(body))
					return newResponse(http.StatusNoContent, ""), nil
				}), nil
			})
			req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/audio/transcriptions", original)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
			req.Header.Set(modelHeader, sealTestModel)
			if tc.getBody {
				req.GetBody = func() (io.ReadCloser, error) {
					if tc.replayErr != nil {
						return nil, tc.replayErr
					}
					return replayed, nil
				}
			}
			resp, err := seal.RoundTrip(req)
			require.Equal(t, 1, original.closes)
			switch {
			case !tc.getBody:
				require.NoError(t, err)
				require.Equal(t, http.StatusPreconditionFailed, resp.StatusCode)
				require.Equal(t, 1, attempts)
				require.Zero(t, responseBody.closes, "the caller owns the returned response")
				resp.Body.Close()
			case tc.replayErr != nil:
				require.ErrorIs(t, err, tc.replayErr)
				require.Nil(t, resp)
				require.Equal(t, 1, attempts)
				require.Equal(t, 1, responseBody.closes)
			default:
				require.NoError(t, err)
				require.Equal(t, http.StatusNoContent, resp.StatusCode)
				require.Equal(t, 2, attempts)
				require.Equal(t, 1, responseBody.closes)
				require.Equal(t, 1, replayed.closes)
				resp.Body.Close()
			}
		})
	}
}

func TestSealJSONRoutingPreservesInjectedBodyAcrossRetries(t *testing.T) {
	for _, contentType := range []string{"application/json", "application/json; charset=utf-8"} {
		t.Run("contentType="+contentType, func(t *testing.T) {
			var bodies []string
			var prefixes []string
			seal := sealTestTransport(func(host string) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					defer req.Body.Close()
					body, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					bodies = append(bodies, string(body))
					require.Equal(t, "test-model", req.Header.Get(modelHeader))
					require.Equal(t, host, req.Header.Get(sealHeader))
					prefixes = append(prefixes, req.Header.Get(cachePrefixHeader))
					if host == sealTestInitial {
						return sealMismatch("next.example"), nil
					}
					return newResponse(http.StatusNoContent, ""), nil
				}), nil
			})
			seal.secret = "test-secret"
			req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`))
			require.NoError(t, err)
			req.Header.Set("Content-Type", contentType)
			resp, err := seal.RoundTrip(req)
			require.NoError(t, err)
			resp.Body.Close()
			require.Len(t, bodies, 2)
			require.Equal(t, bodies[0], bodies[1])
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(bodies[0]), &fields))
			require.NotContains(t, fields, userCacheSecretField)
			require.JSONEq(t, `"iVivfplnoh2hhpE9mmjygP5VqZiCFenuhHb9TfpBpxs"`, string(fields[cacheSaltField]))
			require.NotEmpty(t, prefixes[0])
			require.Equal(t, prefixes[0], prefixes[1])
			require.Empty(t, req.Header.Get(modelHeader))
			require.Empty(t, req.Header.Get(cachePrefixHeader))
			require.Empty(t, req.Header.Get(sealHeader))
		})
	}
}
