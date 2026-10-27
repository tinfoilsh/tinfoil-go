// Package cachesecret provisions the user_cache_secret that scopes the prompt
// cache to one user, and says which requests carry it. transport.WithCacheSecret
// adds it to their bodies.
package cachesecret

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"log/slog"
)

// user_cache_secret provisions the per-user prompt-cache secret defined by the
// secure prompt caching contract. The router derives the request's prefix-cache
// namespace from it: requests carrying the same secret (under the same API
// identity) share cached prompt prefixes, requests carrying different secrets
// cannot observe each other's cache timing.
//
// Resolution order, mirroring the other Tinfoil clients:
//
//  1. a non-empty explicit per-request `user_cache_secret` field in the body,
//  2. the client's UserCacheSecret option,
//  3. the TINFOIL_USER_CACHE_SECRET environment variable,
//  4. a generated secret persisted at ~/.tinfoil/user_cache_secret (0600),
//     shared with other Tinfoil SDKs using the same home directory.
//
// Injection happens in the transport, before the EHBP transport seals the
// body, so the secret is only ever visible to the verified enclave.

const (
	// Field is the router-only request-body field. A non-empty string scopes
	// the prompt cache to that secret.
	Field = "user_cache_secret"

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

// Resolve resolves the client-level secret: the explicit option wins when
// non-empty, then a non-empty environment value, then the persisted (or
// generated) secret.
func Resolve(explicit string, explicitSet bool) string {
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
		slog.Warn("tinfoil: could not generate a user cache secret; requests stay in the tenant-wide cache namespace", "error", err)
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
		slog.Warn("tinfoil: could not persist the user cache secret; using an in-memory secret, so prompt-cache continuity resets when this process exits", "env", userCacheSecretEnv)
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

// PathEligible reports whether the request can carry the field:
// a POST with a body to one of the supported endpoints.
func PathEligible(req *http.Request) bool {
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
