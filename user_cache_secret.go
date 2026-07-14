package tinfoil

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

// user_cache_secret provisions the per-user prompt-cache secret defined by the
// secure prompt caching contract. The router derives the request's prefix-cache
// namespace from it: requests carrying the same secret (under the same API
// identity) share cached prompt prefixes, requests carrying different secrets
// cannot observe each other's cache timing. The secret itself is stripped by
// the router and never reaches the model.
//
// Resolution order, mirroring the other Tinfoil clients:
//
//  1. a non-empty explicit per-request `user_cache_secret` field in the body,
//  2. WithUserCacheSecret,
//  3. the TINFOIL_USER_CACHE_SECRET environment variable,
//  4. a generated secret persisted at ~/.tinfoil/user_cache_secret (0600),
//     shared with the other Tinfoil SDKs on the same machine.
//
// Injection happens in the transport, before the EHBP transport seals the
// body, so the secret is only ever visible to the verified enclave.

const (
	// userCacheSecretField is the router-only request-body field. A non-empty
	// string scopes the prompt cache to that secret.
	userCacheSecretField = "user_cache_secret"

	// userCacheSecretEnv provisions the secret via the environment.
	userCacheSecretEnv = "TINFOIL_USER_CACHE_SECRET"

	// userCacheSecretFile is the persisted-secret path under the home
	// directory. The other Tinfoil SDKs use the same file, so one machine gets
	// one cache namespace across tools.
	userCacheSecretDirName  = ".tinfoil"
	userCacheSecretFileName = "user_cache_secret"
)

// userCacheSecretPaths are the OpenAI-compatible endpoints whose bodies carry
// the field. Matched by suffix with no /v1 prefix required, so custom base
// URLs (path-prefixed proxies or /v1-less roots) still qualify. Other
// endpoints (embeddings, audio, files) are excluded: their engines do not
// prefix-cache and may reject unknown fields.
var userCacheSecretPaths = []string{
	"/chat/completions",
	"/completions",
	"/responses",
}

// WithUserCacheSecret sets the user cache secret explicitly, taking precedence
// over the environment variable and the generated secret. Use one stable value
// per end user: a server holding many end users' conversations should instead
// set the field per request, which always wins over the client-level secret:
//
//	client.Chat.Completions.New(ctx, params,
//		option.WithJSONSet("user_cache_secret", perUserSecret))
//
// An empty string is treated as unset and falls through to the environment or
// generated secret.
func WithUserCacheSecret(secret string) ClientOption {
	return func(c *clientConfig) {
		c.userCacheSecret = secret
		c.userCacheSecretSet = secret != ""
	}
}

// resolveUserCacheSecret resolves the client-level secret: the explicit option
// wins when non-empty, then a non-empty environment value, then the persisted
// (or generated) secret.
func resolveUserCacheSecret(explicit string, explicitSet bool) string {
	if explicitSet && explicit != "" {
		return explicit
	}
	if env, ok := os.LookupEnv(userCacheSecretEnv); ok && env != "" {
		return env
	}
	return loadOrGenerateUserCacheSecret()
}

// newUserCacheSecret returns a fresh 256-bit random secret, hex-encoded.
func newUserCacheSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.WithError(err).Warn("tinfoil: could not generate a user cache secret; client-secret cache isolation is unavailable")
		return ""
	}
	return hex.EncodeToString(b[:])
}

// ephemeralUserCacheSecret is the process-lifetime fallback for when the
// secret cannot be persisted. An unpersisted secret still isolates this
// process's cache namespace, but continuity is lost on restart — like a
// session ID, it silently resets the namespace every deploy — so the fallback
// warns once per process.
var ephemeralUserCacheSecret = sync.OnceValue(func() string {
	secret := newUserCacheSecret()
	if secret != "" {
		log.Warnf("tinfoil: could not persist the user cache secret; using an in-memory secret, so prompt-cache continuity resets when this process exits (set %s or WithUserCacheSecret to pin one)", userCacheSecretEnv)
	}
	return secret
})

// loadOrGenerateUserCacheSecret returns the secret persisted under the user's
// home directory, generating and persisting one on first use. When the home
// directory is unavailable or unwritable it falls back to a process-lifetime
// in-memory secret.
func loadOrGenerateUserCacheSecret() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ephemeralUserCacheSecret()
	}
	dir := filepath.Join(home, userCacheSecretDirName)
	path := filepath.Join(dir, userCacheSecretFileName)

	if err := ensureUserCacheSecretDir(dir); err != nil {
		return ephemeralUserCacheSecret()
	}
	persisted, err := readUserCacheSecret(path)
	if err == nil {
		if persisted != "" {
			return persisted
		}
		return ephemeralUserCacheSecret()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return ephemeralUserCacheSecret()
	}

	secret := newUserCacheSecret()
	if secret == "" {
		return ""
	}
	candidate, err := writeUserCacheSecretCandidate(dir, secret)
	if err != nil {
		return ephemeralUserCacheSecret()
	}
	defer os.Remove(candidate)

	if err := os.Link(candidate, path); err == nil {
		return secret
	} else if !errors.Is(err, fs.ErrExist) {
		return ephemeralUserCacheSecret()
	}
	persisted, err = readUserCacheSecret(path)
	if err != nil || persisted == "" {
		return ephemeralUserCacheSecret()
	}
	return persisted
}

func readUserCacheSecret(path string) (string, error) {
	b, err := readUserCacheSecretFile(path)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", errors.New("user cache secret is not valid UTF-8")
	}
	return strings.TrimSpace(string(b)), nil
}

func validateUserCacheSecretDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("user cache secret directory is not a directory")
	}
	return nil
}

func ensureUserCacheSecretDir(path string) error {
	err := validateUserCacheSecretDir(path)
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return validateUserCacheSecretDir(path)
}

func readUserCacheSecretFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("user cache secret path is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("user cache secret path is not a regular file")
	}
	return io.ReadAll(f)
}

func writeUserCacheSecretCandidate(dir, secret string) (string, error) {
	f, err := os.CreateTemp(dir, userCacheSecretFileName+".tmp-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.WriteString(secret); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

// userCacheSecretTransport injects the client-level secret into request bodies
// on the way out. It sits above the sealing transport (EHBP or pinned TLS), so
// the field is added before the body is encrypted, and below the host-binding
// guard. A non-empty or non-string field already present in the body is never
// overwritten; an empty string is replaced with the client-level secret.
type userCacheSecretTransport struct {
	secret    string
	transport http.RoundTripper
}

func (t *userCacheSecretTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.secret == "" || !userCacheSecretPathEligible(req) || req.GetBody == nil {
		return t.transport.RoundTrip(req)
	}

	raw, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return nil, err
	}

	newBody, changed := injectUserCacheSecret(raw, t.secret)
	out := req.Clone(req.Context())
	if !changed {
		// Not a JSON object, or the caller set a non-empty or non-string field:
		// forward the original bytes untouched.
		out.Body = io.NopCloser(bytes.NewReader(raw))
		return t.transport.RoundTrip(out)
	}

	out.Body = io.NopCloser(bytes.NewReader(newBody))
	out.ContentLength = int64(len(newBody))
	out.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	// Retries below this layer (EHBP key rotation, redirects) must replay the
	// injected body, not the caller's original.
	out.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(newBody)), nil
	}
	return t.transport.RoundTrip(out)
}

// userCacheSecretPathEligible reports whether the request can carry the field:
// a POST with a body to one of the supported endpoints.
func userCacheSecretPathEligible(req *http.Request) bool {
	if req.Method != http.MethodPost || req.Body == nil || req.Body == http.NoBody {
		return false
	}
	for _, p := range userCacheSecretPaths {
		if strings.HasSuffix(req.URL.Path, p) {
			return true
		}
	}
	return false
}

// injectUserCacheSecret adds the field to a JSON-object body, preserving
// number precision across the re-marshal (float64 round-tripping would corrupt
// int64-range values such as seed). It reports false — forward the original
// bytes — for non-object bodies, trailing data, or a body that already carries
// a non-empty or non-string field. An existing empty string is replaced.
func injectUserCacheSecret(raw []byte, secret string) ([]byte, bool) {
	if !utf8.Valid(raw) {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, false
	}
	body := make(map[string]any)
	fieldCount := 0
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, false
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		body[key] = value
		if key == userCacheSecretField {
			fieldCount++
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || !decodeConsumedAll(dec) {
		return nil, false
	}
	if existing, ok := body[userCacheSecretField]; ok {
		value, isString := existing.(string)
		if fieldCount != 1 || !isString || value != "" {
			return nil, false
		}
	}
	body[userCacheSecretField] = secret
	newBody, err := json.Marshal(body)
	if err != nil {
		return nil, false
	}
	return newBody, true
}

// decodeConsumedAll reports whether dec has nothing left but trailing
// whitespace: a follow-up Token read returns io.EOF only at true end of
// input. dec.More() is not enough here — it reports "no more elements" at a
// trailing '}' or ']', so a malformed body like `{...}}` would be
// re-marshaled without its trailing bytes and a request the server rejects
// would quietly become one it accepts.
func decodeConsumedAll(dec *json.Decoder) bool {
	_, err := dec.Token()
	return err == io.EOF
}
