package tinfoil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpprotocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"github.com/tinfoilsh/tinfoil-go/internal/cachesecret"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/internal/verifytest"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// sentRequest is what a cache-secret transport sent over its next transport.
type sentRequest struct {
	req  *http.Request
	body string
}

// captureCacheSecret returns a cache-secret transport for secret over a next
// transport that records each request and its body.
func captureCacheSecret(t *testing.T, secret string) (http.RoundTripper, *[]sentRequest) {
	t.Helper()
	var sent []sentRequest
	next := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body []byte
		if req.Body != nil {
			var err error
			body, err = io.ReadAll(req.Body)
			require.NoError(t, err)
			req.Body.Close()
		}
		sent = append(sent, sentRequest{req: req, body: string(body)})
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})
	return NewCacheSecretTransport(next, secret), &sent
}

func roundTrip(t *testing.T, rt http.RoundTripper, req *http.Request) {
	t.Helper()
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
}

func newBodyRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func requireCacheSecret(t *testing.T, body, want string) {
	t.Helper()
	var fields map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &fields), body)
	require.Equal(t, want, fields[cachesecret.Field], body)
}

func TestCacheSecretTransportInjectsOnEachPath(t *testing.T) {
	for _, path := range []string{
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/responses",
		"/api/v1/chat/completions", // a proxy mounted under a path
		"/chat/completions",        // a base URL without /v1
	} {
		t.Run(path, func(t *testing.T) {
			rt, sent := captureCacheSecret(t, "s1")
			roundTrip(t, rt, newBodyRequest(t, http.MethodPost, "https://router.example"+path, strings.NewReader(`{"model":"m"}`)))
			require.Len(t, *sent, 1)
			got := (*sent)[0]
			requireCacheSecret(t, got.body, "s1")
			require.Equal(t, int64(len(got.body)), got.req.ContentLength)
			require.Equal(t, strconv.Itoa(len(got.body)), got.req.Header.Get("Content-Length"))
		})
	}
}

func TestCacheSecretTransportLeavesOtherRequestsAlone(t *testing.T) {
	const body = `{"model":"m","input":"text"}`
	for _, tc := range []struct {
		name, method, path string
		body               io.Reader
	}{
		{"embeddings", http.MethodPost, "/v1/embeddings", strings.NewReader(body)},
		{"audio", http.MethodPost, "/v1/audio/transcriptions", strings.NewReader(body)},
		{"models", http.MethodGet, "/v1/models", nil},
		{"GET of an eligible path", http.MethodGet, "/v1/responses", nil},
		{"PUT of an eligible path", http.MethodPut, "/v1/chat/completions", strings.NewReader(body)},
		{"a path that only contains an eligible one", http.MethodPost, "/v1/chat/completions/extra", strings.NewReader(body)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, sent := captureCacheSecret(t, "s1")
			roundTrip(t, rt, newBodyRequest(t, tc.method, "https://router.example"+tc.path, tc.body))
			require.Len(t, *sent, 1)
			if tc.body != nil {
				require.Equal(t, body, (*sent)[0].body)
			} else {
				require.Empty(t, (*sent)[0].body)
			}
		})
	}
}

func TestCacheSecretTransportKeepsCallerOwnedValues(t *testing.T) {
	for _, body := range []string{
		`{"model":"m","user_cache_secret":"end-user-7"}`,
		`{"model":"m","user_cache_secret":null}`,
		`{"model":"m","user_cache_secret":42}`,
		`{"model":"m","user_cache_secret":{"nested":""}}`,
		`{"model":"m","user_cache_secret":"","user_cache_secret":""}`,
	} {
		t.Run(body, func(t *testing.T) {
			rt, sent := captureCacheSecret(t, "client-level")
			roundTrip(t, rt, newBodyRequest(t, http.MethodPost, "https://router.example/v1/chat/completions", strings.NewReader(body)))
			require.Equal(t, body, (*sent)[0].body, "the body is sent byte for byte")
		})
	}
}

func TestCacheSecretTransportReplacesAnEmptyString(t *testing.T) {
	rt, sent := captureCacheSecret(t, "client-level")
	body := `{"model":"m","seed":9007199254740993,"user_cache_secret":""}`
	roundTrip(t, rt, newBodyRequest(t, http.MethodPost, "https://router.example/v1/chat/completions", strings.NewReader(body)))
	got := (*sent)[0].body
	requireCacheSecret(t, got, "client-level")
	require.Contains(t, got, `"seed":9007199254740993`, "numbers keep their digits")
}

func TestCacheSecretTransportPassesNonJSONBodiesThrough(t *testing.T) {
	for _, body := range []string{
		"--boundary\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nm\r\n--boundary--\r\n",
		`[{"model":"m"}]`,
		`{"model":"m"}{"model":"n"}`,
		`{"model":"m"`,
		"{\"model\":\"\xff\"}",
	} {
		rt, sent := captureCacheSecret(t, "s1")
		roundTrip(t, rt, newBodyRequest(t, http.MethodPost, "https://router.example/v1/chat/completions", strings.NewReader(body)))
		require.Equal(t, body, (*sent)[0].body)
	}
}

// A body that the caller streams, with no length or GetBody, is read whole,
// and the request that is sent has both for its new body.
func TestCacheSecretTransportInjectsIntoAStreamedBody(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte(`{"model":"m",`))
		pw.Write([]byte(`"stream":true}`))
		pw.Close()
	}()
	req := newBodyRequest(t, http.MethodPost, "https://router.example/v1/chat/completions", pr)
	require.Nil(t, req.GetBody)
	require.Zero(t, req.ContentLength)

	rt, sent := captureCacheSecret(t, "s1")
	roundTrip(t, rt, req)
	got := (*sent)[0]
	requireCacheSecret(t, got.body, "s1")
	require.Contains(t, got.body, `"stream":true`)
	require.Equal(t, int64(len(got.body)), got.req.ContentLength)
}

// A layer below the transport that replays the request, as the attested
// client does after a key rotation, gets the injected body from GetBody, not
// the caller's original.
func TestCacheSecretTransportReplaysTheInjectedBody(t *testing.T) {
	var bodies []string
	read := func(body io.ReadCloser) {
		raw, err := io.ReadAll(body)
		require.NoError(t, err)
		body.Close()
		bodies = append(bodies, string(raw))
	}
	rt := NewCacheSecretTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		read(req.Body)
		require.NotNil(t, req.GetBody)
		replay, err := req.GetBody()
		require.NoError(t, err)
		read(replay)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	}), "s1")
	req := newBodyRequest(t, http.MethodPost, "https://router.example/v1/chat/completions", strings.NewReader(`{"model":"m"}`))
	roundTrip(t, rt, req)
	require.Len(t, bodies, 2)
	require.Equal(t, bodies[0], bodies[1])
	requireCacheSecret(t, bodies[1], "s1")
}

func TestCacheSecretTransportEmptySecretUsesTheProcessSecret(t *testing.T) {
	process := cachesecret.Resolve("")
	require.NotEmpty(t, process)
	for range 2 {
		rt, sent := captureCacheSecret(t, "")
		roundTrip(t, rt, newBodyRequest(t, http.MethodPost, "https://router.example/v1/responses", strings.NewReader(`{"model":"m"}`)))
		requireCacheSecret(t, (*sent)[0].body, process)
	}
}

func TestCacheSecretTransportNilNextUsesTheDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	var got string
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		got = string(raw)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
	})
	roundTrip(t, NewCacheSecretTransport(nil, "s1"), newBodyRequest(t, http.MethodPost, "https://router.example/v1/chat/completions", strings.NewReader(`{"model":"m"}`)))
	requireCacheSecret(t, got, "s1")
}

func TestCacheSecretTransportClosesIdleConnections(t *testing.T) {
	var closes int
	next := &idleCounter{closes: &closes}
	NewCacheSecretTransport(next, "s1").(interface{ CloseIdleConnections() }).CloseIdleConnections()
	require.Equal(t, 1, closes)
}

type idleCounter struct{ closes *int }

func (*idleCounter) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}
func (c *idleCounter) CloseIdleConnections() { *c.closes++ }

// fakeEHBPEnclave is an enclave behind a loopback EHBP proxy: it opens each
// request body with its HPKE key and records the plaintext, next to the bytes
// that crossed the wire. It answers the first rejectFirst requests with a key
// config mismatch, as an enclave whose key rotated does.
type fakeEHBPEnclave struct {
	*httptest.Server
	identity *ehbpidentity.Identity

	mu          sync.Mutex
	wire, plain []string
	rejectFirst int
}

func newFakeEHBPEnclave(t *testing.T) *fakeEHBPEnclave {
	t.Helper()
	id, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	f := &fakeEHBPEnclave{identity: id}
	opened := id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		f.mu.Lock()
		f.plain = append(f.plain, string(raw))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		f.mu.Lock()
		f.wire = append(f.wire, string(raw))
		reject := f.rejectFirst > 0
		f.rejectFirst--
		f.mu.Unlock()
		if reject {
			w.Header().Set("Content-Type", ehbpprotocol.ProblemJSONMediaType)
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"type":"` + ehbpprotocol.KeyConfigProblemType + `","title":"key configuration mismatch"}`))
			return
		}
		opened.ServeHTTP(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

// enclaveClient returns an EnclaveHTTPClient that seals requests to f's key
// and sends them through f as its EHBP proxy, with a verification that attests
// that key.
func (f *fakeEHBPEnclave) enclaveClient(t *testing.T) *EnclaveHTTPClient {
	t.Helper()
	key := f.identity.MarshalPublicKeyHex()
	e := enclave.NewForTest("enclave.example", func() (*verify.VerificationReport, error) {
		return verifytest.NewReport(verifytest.Fields{
			FreshnessExpiresAt: time.Now().Add(time.Hour),
			CryptoMaterial: []document.CryptoMaterialItem{
				{ID: document.CryptoMaterialIDHPKE, Format: document.KeyX25519HPKEV1Format, Data: key},
			},
		}), nil
	}, nil)
	a, err := newAttestedClient(transport.WithEHBP(nil, e), f.URL+"/", "")
	require.NoError(t, err)
	return &EnclaveHTTPClient{Client: a.embedded(), attestedClient: a}
}

// Wrapping an enclave client's transport adds the secret before EHBP seals
// the body: the enclave opens a body that carries it, and the wire never
// carries it in the clear.
func TestCacheSecretTransportIsSealedByTheEnclaveClient(t *testing.T) {
	f := newFakeEHBPEnclave(t)
	client := f.enclaveClient(t)
	client.Transport = NewCacheSecretTransport(client.Transport, "sealed-secret")

	resp, err := client.Post(client.BaseURL()+"v1/chat/completions", "application/json", strings.NewReader(`{"model":"m"}`))
	require.NoError(t, err)
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(got))
	require.JSONEq(t, `{"ok":true}`, string(got), "the response is opened too")

	require.Len(t, f.plain, 1)
	requireCacheSecret(t, f.plain[0], "sealed-secret")
	require.Len(t, f.wire, 1)
	require.NotContains(t, f.wire[0], "sealed-secret", "the body is sealed")
	require.NotContains(t, f.wire[0], "model")
}

// After a key rejection, the enclave client's replay seals the injected body
// again, so that the retry carries the secret too.
func TestCacheSecretTransportSurvivesTheEnclaveClientsReplay(t *testing.T) {
	f := newFakeEHBPEnclave(t)
	f.rejectFirst = 1
	client := f.enclaveClient(t)
	client.Transport = NewCacheSecretTransport(client.Transport, "sealed-secret")

	// A body that can't be read twice by itself.
	req := newBodyRequest(t, http.MethodPost, client.BaseURL()+"v1/responses", io.NopCloser(strings.NewReader(`{"model":"m"}`)))
	resp, err := client.Do(req)
	require.NoError(t, err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, f.wire, 2, "the rejected request is replayed once")
	require.Len(t, f.plain, 1)
	requireCacheSecret(t, f.plain[0], "sealed-secret")
}

// The wrapped client keeps the attested transport's origin restriction, so
// that the secret never leaves for another origin.
func TestCacheSecretTransportKeepsTheOriginRestriction(t *testing.T) {
	f := newFakeEHBPEnclave(t)
	client := f.enclaveClient(t)
	client.Transport = NewCacheSecretTransport(client.Transport, "sealed-secret")
	_, err := client.Post("https://elsewhere.example/v1/chat/completions", "application/json", strings.NewReader(`{"model":"m"}`))
	require.ErrorIs(t, err, ErrConfiguration)
	require.ErrorContains(t, err, "refusing to send request")
	require.Empty(t, f.wire)
}
