// Package cachesecret provisions the user_cache_secret that scopes the prompt
// cache to one user, and says which requests carry it. transport.WithCacheSecret
// adds it to their bodies.
package cachesecret

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// user_cache_secret provisions the per-user prompt-cache secret defined by the
// secure prompt caching contract. The router derives the request's prefix-cache
// namespace from it: requests carrying the same secret (under the same API
// identity) share cached prompt prefixes, requests carrying different secrets
// cannot observe each other's cache timing.
//
// Clients for Tinfoil's inference routes (router discovery and the gateway)
// resolve it in this order; a client for an explicit enclave uses only the
// first two, since other enclaves don't read the field:
//
//  1. a non-empty explicit per-request `user_cache_secret` field in the body,
//  2. the client's UserCacheSecret option,
//  3. a random secret that is generated in memory once per process and that
//     every client in the process shares.
//
// The SDK reads no environment variable or file for the secret. The generated
// secret lasts only as long as the process, so applications that want a
// stable secret across processes or machines pass UserCacheSecret themselves.
//
// Injection happens in the transport, before the EHBP transport seals the
// body, so the secret is only ever visible to the verified enclave.

// Field is the router-only request-body field. A non-empty string scopes the
// prompt cache to that secret.
const Field = "user_cache_secret"

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

// Resolve resolves the client-level secret: the explicit option when it is
// non-empty, and otherwise the secret that is generated once per process.
func Resolve(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return processSecret()
}

// processSecret is the 256-bit random secret, hex-encoded, that every client
// in the process shares when no option is given. It is generated on first use
// and never persisted.
var processSecret = sync.OnceValue(func() string {
	var b [32]byte
	rand.Read(b[:]) // crypto/rand.Read never returns an error; it crashes instead.
	return hex.EncodeToString(b[:])
})

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

// ObjectKeys returns the names of the top-level members of raw, in the order
// that they appear and with repeats kept, which a decode into a map would
// hide. Names are decoded, so an escaped spelling of a name matches it. It
// reports false unless raw is exactly one JSON object with optional
// whitespace around it.
func ObjectKeys(raw []byte) ([]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if start, err := dec.Token(); err != nil || start != json.Delim('{') {
		return nil, false
	}
	keys := []string{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok {
			return nil, false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false
		}
		keys = append(keys, key)
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return keys, true
}
