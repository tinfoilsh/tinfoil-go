package tinfoil

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	require.False(t, cfg.userCacheSecretSet, "an explicit empty secret must be treated as unset")
}

func TestResolveUserCacheSecretPrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Run("explicit option beats environment", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Equal(t, "explicit", resolveUserCacheSecret("explicit", true))
	})

	t.Run("explicit empty falls through to environment", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Equal(t, "from-env", resolveUserCacheSecret("", true))
	})

	t.Run("environment beats generation and touches no file", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "from-env")
		require.Equal(t, "from-env", resolveUserCacheSecret("", false))
		_, err := os.Stat(filepath.Join(home, userCacheSecretDirName))
		require.True(t, os.IsNotExist(err), "an environment-provided secret must not create the secret file")
	})

	t.Run("environment set but empty falls through to generation", func(t *testing.T) {
		t.Setenv(userCacheSecretEnv, "")
		require.Len(t, resolveUserCacheSecret("", false), 64)
		_, err := os.Stat(filepath.Join(home, userCacheSecretDirName, userCacheSecretFileName))
		require.NoError(t, err)
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

func TestUserCacheSecretRejectsInvalidUTF8WithoutRewriting(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	path := filepath.Join(dir, userCacheSecretFileName)
	corrupted := []byte{0xff, 0xfe, 'a'}
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(path, corrupted, 0o600))

	first := resolveUserCacheSecret("", false)
	require.Len(t, first, 64)
	require.Equal(t, first, resolveUserCacheSecret("", false))
	persisted, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, corrupted, persisted)
}

func TestUserCacheSecretAcceptsPermissiveExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX permission bits")
	}
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	path := filepath.Join(dir, userCacheSecretFileName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(path, []byte("shared-secret"), 0o600))
	require.NoError(t, os.Chmod(dir, 0o777))
	require.NoError(t, os.Chmod(path, 0o666))

	require.Equal(t, "shared-secret", resolveUserCacheSecret("", false))
	requireFileMode(t, dir, 0o777)
	requireFileMode(t, path, 0o666)
}

func TestUserCacheSecretLeavesBlankFileUntouched(t *testing.T) {
	unsetUserCacheSecretEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, userCacheSecretDirName)
	path := filepath.Join(dir, userCacheSecretFileName)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(path, []byte("  \n"), 0o600))

	first := resolveUserCacheSecret("", false)
	require.Len(t, first, 64)
	require.Equal(t, first, resolveUserCacheSecret("", false))
	written, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("  \n"), written)
}

func TestUserCacheSecretConcurrentProcesses(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, userCacheSecretDirName, userCacheSecretFileName)
	secrets := runUserCacheSecretContenders(t, home, userCacheSecretContenderCount)
	for _, secret := range secrets {
		require.Equal(t, secrets[0], secret, "all processes must adopt the elected value")
		require.Len(t, secret, 64)
	}
	persisted, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, secrets[0], strings.TrimSpace(string(persisted)))
	requireFileMode(t, path, 0o600)
}

func TestUserCacheSecretSubprocess(t *testing.T) {
	if os.Getenv("TINFOIL_CACHE_SECRET_HELPER") != "1" {
		return
	}
	_ = os.Unsetenv(userCacheSecretEnv)
	fmt.Println("ready")
	var release [1]byte
	if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(resolveUserCacheSecret("", false))
	os.Exit(0)
}

const userCacheSecretContenderCount = 8

type userCacheSecretContender struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr bytes.Buffer
}

func runUserCacheSecretContenders(t *testing.T, home string, count int) []string {
	t.Helper()
	contenders := make([]userCacheSecretContender, count)
	for i := range contenders {
		cmd := exec.Command(os.Args[0], "-test.run=^TestUserCacheSecretSubprocess$")
		cmd.Env = userCacheSecretHelperEnv(home)
		stdin, err := cmd.StdinPipe()
		require.NoError(t, err)
		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)
		contenders[i] = userCacheSecretContender{
			cmd:    cmd,
			stdin:  stdin,
			stdout: bufio.NewReader(stdout),
		}
		cmd.Stderr = &contenders[i].stderr
		require.NoError(t, cmd.Start())
		ready, err := contenders[i].stdout.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "ready", strings.TrimSpace(ready))
	}

	for i := range contenders {
		_, err := contenders[i].stdin.Write([]byte{1})
		require.NoError(t, err)
		require.NoError(t, contenders[i].stdin.Close())
	}

	secrets := make([]string, count)
	for i := range contenders {
		secret, err := contenders[i].stdout.ReadString('\n')
		require.NoError(t, err)
		waitErr := contenders[i].cmd.Wait()
		require.NoError(t, waitErr, contenders[i].stderr.String())
		secrets[i] = strings.TrimSpace(secret)
	}
	return secrets
}

func userCacheSecretHelperEnv(home string) []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "HOME=") ||
			strings.HasPrefix(value, "USERPROFILE=") ||
			strings.HasPrefix(value, userCacheSecretEnv+"=") ||
			strings.HasPrefix(value, "TINFOIL_CACHE_SECRET_HELPER=") {
			continue
		}
		env = append(env, value)
	}
	return append(
		env,
		"HOME="+home,
		"USERPROFILE="+home,
		"TINFOIL_CACHE_SECRET_HELPER=1",
	)
}

func requireFileMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, mode, info.Mode().Perm())
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

func TestUserCacheSecretTransportLeavesStreamingBodyUntouched(t *testing.T) {
	const raw = `{"model":"m"}`
	var got []byte
	transport := captureTransport("s1", &got, nil)
	req, err := http.NewRequest(
		http.MethodPost,
		"https://enclave.example.com/v1/chat/completions",
		io.NopCloser(strings.NewReader(raw)),
	)
	require.NoError(t, err)
	require.Nil(t, req.GetBody)

	_, err = transport.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, raw, string(got))
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
			require.Equal(t, "client-level", body[userCacheSecretField])
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
	require.Equal(t, "s1", body[userCacheSecretField])
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

	_, err = oai.Chat.Completions.New(context.Background(), params,
		option.WithJSONSet(userCacheSecretField, ""))
	require.NoError(t, err)
	require.Equal(t, "client-level", received[userCacheSecretField],
		"an empty per-request field must be replaced with the client-level secret")
}
