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
//  1. an explicit per-request `user_cache_secret` field in the body (never
//     overwritten here),
//  2. WithUserCacheSecret,
//  3. the TINFOIL_USER_CACHE_SECRET environment variable,
//  4. a generated secret persisted at ~/.tinfoil/user_cache_secret (0600),
//     shared with the other Tinfoil SDKs on the same machine.
//
// Injection happens in the transport, before the EHBP transport seals the
// body, so the secret is only ever visible to the verified enclave.

const (
	// userCacheSecretField is the router-only request-body field. A non-empty
	// string scopes the prompt cache to that secret; an absent or empty value
	// leaves the request in the tenant-wide namespace.
	userCacheSecretField = "user_cache_secret"

	// userCacheSecretEnv provisions the secret via the environment. Setting it
	// to an empty string disables generation entirely (tenant-wide caching),
	// which is the right call for pooled multi-user deployments that would
	// otherwise mint a fresh namespace per container.
	userCacheSecretEnv = "TINFOIL_USER_CACHE_SECRET"

	// userCacheSecretFile is the persisted-secret path under the home
	// directory. The other Tinfoil SDKs use the same file, so one machine gets
	// one cache namespace across tools.
	userCacheSecretDirName  = ".tinfoil"
	userCacheSecretFileName = "user_cache_secret"
)

// userCacheSecretPaths are the OpenAI-compatible endpoints whose bodies carry
// the field. Matched by suffix so a proxy base URL with a path prefix still
// qualifies. Other endpoints (embeddings, audio, files) are excluded: their
// engines do not prefix-cache and may reject unknown fields.
var userCacheSecretPaths = []string{
	"/v1/chat/completions",
	"/v1/completions",
	"/v1/responses",
}

// WithUserCacheSecret sets the user cache secret explicitly, taking precedence
// over the environment variable and the generated secret. Use one stable value
// per end user: a server holding many end users' conversations should instead
// set the field per request, which always wins over the client-level secret:
//
//	client.Chat.Completions.New(ctx, params,
//		option.WithJSONSet("user_cache_secret", perUserSecret))
//
// An empty string disables injection and generation entirely, leaving every
// request in the tenant-wide cache namespace.
func WithUserCacheSecret(secret string) ClientOption {
	return func(c *clientConfig) {
		c.userCacheSecret = secret
		c.userCacheSecretSet = true
	}
}

// resolveUserCacheSecret resolves the client-level secret: the explicit option
// wins, then the environment, then the persisted (or generated) secret. An
// empty result means injection is disabled.
func resolveUserCacheSecret(explicit string, explicitSet bool) string {
	if explicitSet {
		return explicit
	}
	if env, ok := os.LookupEnv(userCacheSecretEnv); ok {
		return env
	}
	return loadOrGenerateUserCacheSecret()
}

// newUserCacheSecret returns a fresh 256-bit random secret, hex-encoded.
func newUserCacheSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Never fall back to a weak secret: no secret means tenant-wide
		// caching, which is safe.
		log.WithError(err).Warn("tinfoil: could not generate a user cache secret; requests stay in the tenant-wide cache namespace")
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

	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}

	secret := newUserCacheSecret()
	if secret == "" {
		return ""
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ephemeralUserCacheSecret()
	}

	// O_EXCL so a concurrent first run loses the race cleanly: the loser
	// re-reads and adopts the winner's secret instead of splitting the
	// machine's namespace between two values.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case err == nil:
		_, werr := f.WriteString(secret)
		cerr := f.Close()
		if werr == nil && cerr == nil {
			return secret
		}
	case errors.Is(err, fs.ErrExist):
		if b, rerr := os.ReadFile(path); rerr == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	default:
		return ephemeralUserCacheSecret()
	}

	// The file exists but is blank or torn: rewrite it in place.
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		return ephemeralUserCacheSecret()
	}
	return secret
}

// userCacheSecretTransport injects the client-level secret into request bodies
// on the way out. It sits above the sealing transport (EHBP or pinned TLS), so
// the field is added before the body is encrypted, and below the host-binding
// guard. A field already present in the body is never overwritten — an
// explicit per-request value, including an explicit empty string (= opt out
// for that request), always wins.
type userCacheSecretTransport struct {
	secret    string
	transport http.RoundTripper
}

func (t *userCacheSecretTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.secret == "" || !userCacheSecretPathEligible(req) {
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
		// Not a JSON object, or the caller set the field: forward the
		// original bytes untouched.
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
// the field.
func injectUserCacheSecret(raw []byte, secret string) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil || dec.More() || body == nil {
		return nil, false
	}
	if _, ok := body[userCacheSecretField]; ok {
		return nil, false
	}
	body[userCacheSecretField] = secret
	newBody, err := json.Marshal(body)
	if err != nil {
		return nil, false
	}
	return newBody, true
}
