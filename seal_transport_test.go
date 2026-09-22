package tinfoil

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

func sealTestClient(t *testing.T) *client.SecureClient {
	t.Helper()
	s, err := client.NewSecureClient("initial.example", "org/repo", nil)
	require.NoError(t, err)
	return s
}

func sealMismatch(enclave string) *http.Response {
	resp := newResponse(http.StatusPreconditionFailed, "")
	resp.Header.Set(sealHeader, enclave)
	return resp
}

func TestSealRerouteUpdatesEnclaveAfterVerification(t *testing.T) {
	initial := sealTestClient(t)
	verificationErr := errors.New("verification failed")
	var nextBuilds int
	seal, err := newSealTransport(initial, func(s *client.SecureClient) (http.RoundTripper, error) {
		if s.Enclave() != initial.Enclave() {
			nextBuilds++
			if nextBuilds == 1 {
				return nil, verificationErr
			}
		}
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if s.Enclave() == initial.Enclave() && req.URL.Path == "/reroute" {
				return sealMismatch("next.example"), nil
			}
			return newResponse(http.StatusNoContent, ""), nil
		}), nil
	})
	require.NoError(t, err)
	c := &Client{active: seal.enclave, httpClient: &http.Client{Transport: seal}}
	_, err = c.HTTPClient().Get("https://gateway.example/reroute")
	require.ErrorIs(t, err, verificationErr)
	require.Equal(t, initial.Enclave(), c.Enclave(), "failed verification must not change the enclave")
	resp, err := c.HTTPClient().Get("https://gateway.example/reroute")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, "next.example", c.Enclave())
}

func TestSealRerouteRebuildsStaleEnclaveEntry(t *testing.T) {
	initial := sealTestClient(t)
	var builds int
	seal, err := newSealTransport(initial, func(*client.SecureClient) (http.RoundTripper, error) {
		builds++
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return newResponse(http.StatusNoContent, ""), nil
		}), nil
	})
	require.NoError(t, err)
	// Model a cached client's endpoint changing after automatic key recovery.
	seal.active.secure = initial.ForEnclave("replacement.example")
	selected, err := seal.follow(initial.ForEnclave(initial.Enclave()))
	require.NoError(t, err)
	require.Equal(t, initial.Enclave(), selected.secure.Enclave())
	require.Equal(t, 2, builds, "a stale cache entry must be rebuilt for its requested enclave")
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
			initial := sealTestClient(t)
			var attempts int
			seal, err := newSealTransport(initial, func(s *client.SecureClient) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					defer req.Body.Close()
					attempts++
					if s.Enclave() == initial.Enclave() {
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
			require.NoError(t, err)
			req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/audio/transcriptions", original)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
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
			initial := sealTestClient(t)
			var bodies []string
			var prefixes []string
			seal, err := newSealTransport(initial, func(s *client.SecureClient) (http.RoundTripper, error) {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					defer req.Body.Close()
					body, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					bodies = append(bodies, string(body))
					require.Equal(t, "test-model", req.Header.Get(modelHeader))
					require.Equal(t, s.Enclave(), req.Header.Get(sealHeader))
					prefixes = append(prefixes, req.Header.Get(cachePrefixHeader))
					if s.Enclave() == initial.Enclave() {
						return sealMismatch("next.example"), nil
					}
					return newResponse(http.StatusNoContent, ""), nil
				}), nil
			})
			require.NoError(t, err)
			rt := &userCacheSecretTransport{secret: "test-secret", transport: seal}
			req, err := http.NewRequest(http.MethodPost, "https://gateway.example/v1/chat/completions", strings.NewReader(`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`))
			require.NoError(t, err)
			req.Header.Set("Content-Type", contentType)
			resp, err := rt.RoundTrip(req)
			require.NoError(t, err)
			resp.Body.Close()
			require.Len(t, bodies, 2)
			require.Equal(t, bodies[0], bodies[1])
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(bodies[0]), &fields))
			require.JSONEq(t, `"test-secret"`, string(fields[userCacheSecretField]))
			require.NotEmpty(t, prefixes[0])
			require.Equal(t, prefixes[0], prefixes[1])
			require.Empty(t, req.Header.Get(modelHeader))
			require.Empty(t, req.Header.Get(cachePrefixHeader))
			require.Empty(t, req.Header.Get(sealHeader))
		})
	}
}
