package transport

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"unicode/utf8"

	"github.com/tinfoilsh/tinfoil-go/internal/cachesecret"
)

// userCacheSecretTransport injects the client-level secret into request bodies
// on the way out. It sits above the sealing transport (EHBP or pinned TLS), so
// the field is added before the body is encrypted, and below the origin
// restriction. A non-empty or non-string field already present in the body is
// never overwritten; an empty string is replaced with the client-level secret.
type userCacheSecretTransport struct {
	secret    string
	transport http.RoundTripper
}

// WithCacheSecret adds secret to the bodies of the requests that carry it, as
// userCacheSecretTransport describes, before sending them over next. An empty
// secret returns next.
func WithCacheSecret(next http.RoundTripper, secret string) http.RoundTripper {
	if secret == "" {
		return next
	}
	return &userCacheSecretTransport{secret: secret, transport: next}
}

func (t *userCacheSecretTransport) CloseIdleConnections() {
	closeIdleConnections(t.transport)
}

func (t *userCacheSecretTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.secret == "" || !cachesecret.PathEligible(req) {
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
		if key == cachesecret.Field {
			fieldCount++
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') || !decodeConsumedAll(dec) {
		return nil, false
	}
	if existing, ok := body[cachesecret.Field]; ok {
		value, isString := existing.(string)
		if fieldCount != 1 || !isString || value != "" {
			return nil, false
		}
	}
	body[cachesecret.Field] = secret
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
