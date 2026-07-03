package tinfoil

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
)

// unsetUserCacheSecretEnv removes TINFOIL_USER_CACHE_SECRET for the test (a
// developer .env loaded by TestMain may set it) and restores it afterwards.
func unsetUserCacheSecretEnv(t *testing.T) {
	t.Helper()
	t.Setenv(userCacheSecretEnv, "placeholder") // registers restoration
	require.NoError(t, os.Unsetenv(userCacheSecretEnv))
}

func TestWithUserCacheSecretOption(t *testing.T) {
	cfg := &clientConfig{}
	WithUserCacheSecret("s1")(cfg)
	require.Equal(t, "s1", cfg.userCacheSecret)
	require.True(t, cfg.userCacheSecretSet)

	cfg = &clientConfig{}
	WithUserCacheSecret("")(cfg)
	require.Empty(t, cfg.userCacheSecret)
	require.True(t, cfg.userCacheSecretSet, "an explicit empty secret must still count as set (it disables provisioning)")
}

func TestResolveUserCacheSecretPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Run("explicit option beats environment", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Equal(t, "explicit", resolveUserCacheSecret("explicit", true))
	})

	t.Run("explicit empty disables even with environment set", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Empty(t, resolveUserCacheSecret("", true))
	})

	t.Run("environment beats generation and touches no file", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Equal(t, "from-env", resolveUserCacheSecret("", false))
		_, err := os.Stat(filepath.Join(home, userCacheSecretDirName))
		require.True(t, os.IsNotExist(err), "an environment-provided secret must not create the secret file")
	})

	t.Run("environment set but empty disables generation", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "")
		require.Empty(t, resolveUserCacheSecret("", false))
		_, err := os.Stat(filepath.Join(home, userCacheSecretDirName))
		require.True(t, os.IsNotExist(err), "a disabled secret must not create the secret file")
	})
}

func TestUserCacheSecretGenerateAndPersist(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	first := resolveUserCacheSecret("", false)
	require.Len(t, first, 64, "expected a hex-encoded 256-bit secret")

	path := filepath.Join(home, userCacheSecretDirName, userCacheSecretFileName)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	// A second resolution (a new client, or another SDK on the same machine)
	// must reuse the persisted secret, not mint a new namespace.
	require.Equal(t, first, resolveUserCacheSecret("", false))
}

func TestUserCacheSecretAdoptsExistingFile(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	// Trailing newline: the file may be hand-edited or written by another SDK.
	require.NoError(t, os.WriteFile(filepath.Join(dir, userCacheSecretFileName), []byte("shared-secret\n"), 0o600))

	require.Equal(t, "shared-secret", resolveUserCacheSecret("", false))
}

func TestUserCacheSecretRewritesBlankFile(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	path := filepath.Join(dir, userCacheSecretFileName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(path, []byte("  \n"), 0o600))

	secret := resolveUserCacheSecret("", false)
	require.Len(t, secret, 64)

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, secret, strings.TrimSpace(string(written)), "a blank file must be replaced with the generated secret")
}

func TestUserCacheSecretFallsBackWithoutHome(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	t.Setenv("HOME", "")

	first := resolveUserCacheSecret("", false)
	require.NotEmpty(t, first, "no home directory must still yield a process-lifetime secret")
	require.Equal(t, first, resolveUserCacheSecret("", false), "the in-memory fallback must be stable within the process")
}

func TestUserCacheSecretFallsBackWhenHomeNotADirectory(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	homeFile := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(homeFile, []byte("x"), 0o600))
	t.Setenv("HOME", homeFile)

	require.NotEmpty(t, resolveUserCacheSecret("", false))
}

// captureTransport returns a userCacheSecretTransport whose inner round
// tripper records the outgoing body.
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
			require.Equal(t, "s1", body[userCacheSecretField])

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
		var got []byte
		transport := captureTransport("s1", &got, nil)
		const raw = `{"model":"m","input":"text"}`
		_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com/v1/embeddings", raw))
		require.NoError(t, err)
		require.Equal(t, raw, string(got))
	})

	t.Run("GET with no body is forwarded as-is", func(t *testing.T) {
		transport := captureTransport("s1", nil, nil)
		req, err := http.NewRequest(http.MethodGet, "https://enclave.example.com/v1/models", nil)
		require.NoError(t, err)
		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("empty secret disables injection", func(t *testing.T) {
		var got []byte
		transport := captureTransport("", &got, nil)
		const raw = `{"model":"m"}`
		_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com/v1/chat/completions", raw))
		require.NoError(t, err)
		require.Equal(t, raw, string(got))
	})
}

func TestUserCacheSecretTransportNeverClobbers(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"explicit per-request secret", `{"model":"m","user_cache_secret":"end-user-7"}`},
		{"explicit empty opt-out", `{"model":"m","user_cache_secret":""}`},
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

func TestUserCacheSecretTransportNonObjectBodies(t *testing.T) {
	for _, raw := range []string{`not json`, `[1,2,3]`, `null`, `{"model":"m"} trailing`} {
		t.Run(raw, func(t *testing.T) {
			var got []byte
			transport := captureTransport("s1", &got, nil)
			_, err := transport.RoundTrip(postJSONRequest(t, "https://enclave.example.com/v1/chat/completions", raw))
			require.NoError(t, err)
			require.Equal(t, raw, string(got), "bodies the router-side schema would reject must be forwarded untouched")
		})
	}
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
	require.Equal(t, "client-level", received[userCacheSecretField])

	_, err = oai.Chat.Completions.New(context.Background(), params,
		option.WithJSONSet(userCacheSecretField, "end-user-7"))
	require.NoError(t, err)
	require.Equal(t, "end-user-7", received[userCacheSecretField],
		"a per-request field must win over the client-level secret")
}
