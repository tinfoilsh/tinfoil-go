package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/cachesecret"
)

func captureTransport(secret string, gotBody *[]byte, gotReq **http.Request) *userCacheSecretTransport {
	return &userCacheSecretTransport{
		secret: secret,
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Body != nil {
				b, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				*gotBody = b
			}
			if gotReq != nil {
				*gotReq = req
			}
			return newResponse(http.StatusOK, "ok"), nil
		}),
	}
}

func postJSONRequest(t *testing.T, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestUserCacheSecretTransportInjects(t *testing.T) {
	paths := []string{
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/responses",
		"/api/v1/chat/completions", // proxy base URL with a path prefix
		"/chat/completions",        // custom base URL without a /v1 root
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			var got []byte
			var sent *http.Request
			transport := captureTransport("s1", &got, &sent)

			req := postJSONRequest(t, "https://enclave.example.com"+path, `{"model":"m"}`)
			resp, err := transport.RoundTrip(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			var body map[string]any
			require.NoError(t, json.Unmarshal(got, &body))
			require.Equal(t, "s1", body[cachesecret.Field])

			// Length metadata and the replayable body must describe the
			// injected bytes: retries below this layer (EHBP key rotation)
			// re-send via GetBody.
			require.Equal(t, int64(len(got)), sent.ContentLength)
			require.Equal(t, strconv.Itoa(len(got)), sent.Header.Get("Content-Length"))
			require.NotNil(t, sent.GetBody)
			replay, err := sent.GetBody()
			require.NoError(t, err)
			replayed, err := io.ReadAll(replay)
			require.NoError(t, err)
			require.Equal(t, got, replayed)
		})
	}
}

func TestUserCacheSecretTransportSkipsIneligibleRequests(t *testing.T) {
	t.Run("non-allowlisted endpoint forwards the body untouched", func(t *testing.T) {
		for _, path := range []string{"/v1/embeddings", "/embeddings"} {
			var got []byte
			transport := captureTransport("s1", &got, nil)
			const raw = `{"model":"m","input":"text"}`
			_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com"+path, raw))
			require.NoError(t, err)
			require.Equal(t, raw, string(got))
		}
	})

	t.Run("GET with no body is forwarded as-is", func(t *testing.T) {
		transport := captureTransport("s1", nil, nil)
		req, err := http.NewRequest(http.MethodGet, "https://enclave.example.com/v1/models", nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("missing resolved secret skips injection", func(t *testing.T) {
		var got []byte
		transport := captureTransport("", &got, nil)
		const raw = `{"model":"m"}`
		_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com/v1/chat/completions", raw))
		require.NoError(t, err)
		require.Equal(t, raw, string(got))
	})
}

func TestUserCacheSecretTransportInjectsIntoStreamingBody(t *testing.T) {
	var got []byte
	var sent *http.Request
	transport := captureTransport("s1", &got, &sent)
	req, err := http.NewRequest(
		http.MethodPost,
		"https://enclave.example.com/v1/chat/completions",
		io.NopCloser(strings.NewReader(`{"model":"m"}`)),
	)
	require.NoError(t, err)
	require.Nil(t, req.GetBody)

	_, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, `{"model":"m","user_cache_secret":"s1"}`, string(got))
	require.Equal(t, int64(len(got)), sent.ContentLength)
	require.NotNil(t, sent.GetBody)
	replay, err := sent.GetBody()
	require.NoError(t, err)
	replayed, err := io.ReadAll(replay)
	require.NoError(t, err)
	require.Equal(t, got, replayed)
}

func TestUserCacheSecretTransportNeverClobbersNonEmptyOrNonStringValues(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"explicit per-request secret", `{"model":"m","user_cache_secret":"end-user-7"}`},
		{"non-string per-request value", `{"model":"m","user_cache_secret":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []byte
			transport := captureTransport("client-level", &got, nil)
			_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com/v1/chat/completions", tc.raw))
			require.NoError(t, err)
			require.Equal(t, tc.raw, string(got), "a body that already carries the field must pass through byte-identical")
		})
	}
}

func TestUserCacheSecretTransportReplacesEmptyPerRequestSecret(t *testing.T) {
	for _, raw := range []string{
		`{"model":"m","seed":9007199254740993,"user_cache_secret":""}`,
		`{"model":"m","user_cache_secre\u0074":""}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var got []byte
			var sent *http.Request
			transport := captureTransport("client-level", &got, &sent)
			_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com/v1/chat/completions", raw))
			require.NoError(t, err)

			var body map[string]any
			decoder := json.NewDecoder(bytes.NewReader(got))
			decoder.UseNumber()
			require.NoError(t, decoder.Decode(&body))
			require.Equal(t, "client-level", body[cachesecret.Field])
			if seed, ok := body["seed"]; ok {
				require.Equal(t, json.Number("9007199254740993"), seed)
			}
			replay, err := sent.GetBody()
			require.NoError(t, err)
			replayed, err := io.ReadAll(replay)
			require.NoError(t, err)
			require.Equal(t, got, replayed)
		})
	}
}

func TestUserCacheSecretTransportLeavesDuplicateFieldsUntouched(t *testing.T) {
	const raw = `{"user_cache_secret":"","user_cache_secret":""}`
	var got []byte
	transport := captureTransport("client-level", &got, nil)
	_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com/v1/chat/completions", raw))
	require.NoError(t, err)
	require.Equal(t, raw, string(got))
}

func TestUserCacheSecretTransportNonObjectBodies(t *testing.T) {
	// The trailing '}' / ']' cases are the regression: dec.More() reports
	// "no more elements" at either byte, so they used to be re-marshaled
	// with the trailing bytes silently dropped.
	for _, raw := range []string{
		`not json`,
		`[1,2,3]`,
		`null`,
		`{"model":"m"} trailing`,
		`{"model":"m"}}`,
		`{"model":"m"}]`,
		`{"model":"m"}} garbage`,
	} {
		t.Run(raw, func(t *testing.T) {
			var got []byte
			transport := captureTransport("s1", &got, nil)
			_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com/v1/chat/completions", raw))
			require.NoError(t, err)
			require.Equal(t, raw, string(got), "bodies the router-side schema would reject must be forwarded untouched")
		})
	}
}

func TestUserCacheSecretTransportInvalidUTF8(t *testing.T) {
	raw := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	var got []byte
	transport := captureTransport("s1", &got, nil)
	req, err := http.NewRequest(
		http.MethodPost,
		"https://enclave.example.com/v1/chat/completions",
		bytes.NewReader(raw),
	)
	require.NoError(t, err)
	_, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, raw, got, "invalid UTF-8 JSON must be forwarded byte-for-byte")
}

func TestUserCacheSecretTransportAllowsTrailingWhitespace(t *testing.T) {
	// Trailing whitespace is not trailing data: strict JSON parsers accept
	// it, so the injection must too — clients routinely end bodies with \n.
	var got []byte
	transport := captureTransport("s1", &got, nil)
	_, err := transport.RoundTrip(postJSONRequest(t,
		"https://enclave.example.com/v1/chat/completions", "{\"model\":\"m\"}\n\t "))
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(got, &body))
	require.Equal(t, "s1", body[cachesecret.Field])
}

func TestUserCacheSecretTransportPreservesNumberPrecision(t *testing.T) {
	// 2^53+1 is not representable as float64; naive decoding would corrupt it.
	var got []byte
	transport := captureTransport("s1", &got, nil)
	_, err := transport.RoundTrip(postJSONRequest(t,
		"https://enclave.example.com/v1/chat/completions", `{"model":"m","seed":9007199254740993}`))
	require.NoError(t, err)
	require.Contains(t, string(got), `"seed":9007199254740993`)
}

// TestUserCacheSecretThroughOpenAIClient drives the real OpenAI client through
// the injection transport to a local server, pinning that the secret rides
// requests exactly as the SDK builds them — and that a per-request field set
// via request options wins over the client-level secret.
func TestUserCacheSecretThroughOpenAIClient(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/chat/completions", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer server.Close()

	httpClient := &http.Client{Transport: &userCacheSecretTransport{
		secret:    "client-level",
		transport: http.DefaultTransport,
	}}
	oai := openai.NewClient(
		option.WithAPIKey("test"),
		option.WithBaseURL(server.URL+"/v1/"),
		option.WithHTTPClient(httpClient),
	)

	params := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{openai.UserMessage("hi")},
		Model:    "m",
	}

	_, err := oai.Chat.Completions.New(context.Background(), params)
	require.NoError(t, err)
	require.Equal(t, "client-level", received[cachesecret.Field])

	_, err = oai.Chat.Completions.New(context.Background(), params,
		option.WithJSONSet(cachesecret.Field, "end-user-7"))
	require.NoError(t, err)
	require.Equal(t, "end-user-7", received[cachesecret.Field],
		"a per-request field must win over the client-level secret")

	_, err = oai.Chat.Completions.New(context.Background(), params,
		option.WithJSONSet(cachesecret.Field, ""))
	require.NoError(t, err)
	require.Equal(t, "client-level", received[cachesecret.Field],
		"an empty per-request field must be replaced with the client-level secret")
}

func TestCacheSecretBodyCanReplay(t *testing.T) {
	var bodies []string
	read := func(body io.ReadCloser) {
		raw, err := io.ReadAll(body)
		require.NoError(t, err)
		body.Close()
		bodies = append(bodies, string(raw))
	}
	transport := WithCacheSecret(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		read(req.Body)
		// The enclave stack below replays the body once after a key rejection.
		require.NotNil(t, req.GetBody)
		replay, err := req.GetBody()
		require.NoError(t, err)
		read(replay)
		return newResponse(http.StatusOK, "ok"), nil
	}), "cache-secret")
	req, err := http.NewRequest(http.MethodPost, "https://enclave.example/v1/chat/completions", io.NopCloser(strings.NewReader(`{"model":"gpt-oss-120b"}`)))
	require.NoError(t, err)
	require.Nil(t, req.GetBody)
	resp, err := transport.RoundTrip(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Len(t, bodies, 2)
	require.Equal(t, bodies[0], bodies[1])
	var fields map[string]any
	require.NoError(t, json.Unmarshal([]byte(bodies[1]), &fields))
	require.Equal(t, "cache-secret", fields[cachesecret.Field])
}

func TestCacheSecretClosesIdleConnections(t *testing.T) {
	inner := &idleCountingTransport{}
	transport := WithCacheSecret(inner, "cache-secret")
	transport.(interface{ CloseIdleConnections() }).CloseIdleConnections()
	require.Equal(t, 1, inner.closes)
}
