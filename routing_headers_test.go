package tinfoil

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const chatPath = "/v1/chat/completions"

// routedHeaders returns the headers the gateway would see, and the body that reached the sealing transport.
func routedHeaders(t *testing.T, body, secret, path string, callerHeaders map[string]string) (http.Header, string) {
	t.Helper()
	var seen *http.Request
	var forwarded []byte
	rt := &sealedBodyTransport{
		secret:  secret,
		routing: true,
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			seen, forwarded = req, nil
			if req.Body != nil {
				forwarded, _ = io.ReadAll(req.Body)
			}
			return newResponse(http.StatusOK, "ok"), nil
		}),
	}
	req := postJSONRequest(t, "https://gateway.example.com"+path, body)
	for name, value := range callerHeaders {
		req.Header.Set(name, value)
	}
	_, err := rt.RoundTrip(req)
	require.NoError(t, err)
	return seen.Header, string(forwarded)
}

// expectedPrefix recomputes the wire format independently of the implementation.
func expectedPrefix(secret, head string) string {
	sum := sha256.Sum256([]byte(secret + "\x00" + head))
	return hex.EncodeToString(sum[:])
}

// The prefix hashes the head of the prompt, whichever field the endpoint carries it in.
func TestRoutingHeadersHashThePromptHead(t *testing.T) {
	for _, c := range []struct{ name, path, body, head string }{
		{"messages", chatPath,
			`{"model":"m","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hi"}]}`,
			`{"content":"be brief","role":"system"}`},
		{"instructions outrank input", "/v1/responses",
			`{"model":"m","instructions":"be brief","input":[{"role":"user","content":"hi"}]}`, `"be brief"`},
		{"input", "/v1/responses", `{"model":"m","input":[{"role":"user","content":"hi"}]}`,
			`{"content":"hi","role":"user"}`},
		{"plain prompt", "/v1/completions", `{"model":"m","prompt":"once upon a time"}`, `"once upon a time"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			headers, _ := routedHeaders(t, c.body, "s1", c.path, nil)
			require.Equal(t, "m", headers.Get(modelHeader))
			require.Equal(t, expectedPrefix("s1", c.head), headers.Get(cachePrefixHeader))
		})
	}
}

// With no secret or no prompt there is nothing to hash, and the gateway routes on the model alone.
func TestRoutingHeadersOmitThePrefixWhenThereIsNothingToHash(t *testing.T) {
	for _, c := range []struct{ name, path, body, secret string }{
		{"endpoint that carries no secret", "/v1/embeddings", `{"model":"m","input":"hi"}`, "s1"},
		{"no secret", chatPath, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, ""},
		{"no prompt", chatPath, `{"model":"m","messages":[]}`, "s1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			headers, _ := routedHeaders(t, c.body, c.secret, c.path, nil)
			require.Equal(t, "m", headers.Get(modelHeader))
			require.Empty(t, headers.Get(cachePrefixHeader))
		})
	}
}

func TestRoutingHeadersKeepAConversationOnOnePrefix(t *testing.T) {
	first := `{"role":"user","content":"hi"}`
	prefix := func(model, messages string) string {
		headers, _ := routedHeaders(t, `{"model":"`+model+`","messages":[`+messages+`]}`, "s1", chatPath, nil)
		return headers.Get(cachePrefixHeader)
	}
	turn1 := prefix("m", first)

	// A later turn must hash the same, or the gateway sends it to a replica with a cold cache.
	require.Equal(t, turn1, prefix("m", first+`,{"role":"assistant","content":"hello"},{"role":"user","content":"more"}`))
	// A different model shares the prefix: the gateway picks the pool by model first.
	require.Equal(t, turn1, prefix("other", first))
	require.NotEqual(t, turn1, prefix("m", `{"role":"user","content":"bye"}`))
}

// A secret in the body keys the hash, so two users of one client never share a prefix — and it never
// travels in a header, so the gateway cannot link the prefix back to a prompt or compute it itself.
func TestRoutingHeadersKeyOnThePerRequestSecret(t *testing.T) {
	head := `{"role":"user","content":"hi"}`
	body := func(secret string) string {
		return `{"model":"m","messages":[` + head + `],"user_cache_secret":"` + secret + `"}`
	}
	userA, _ := routedHeaders(t, body("a-secret"), "client", chatPath, nil)
	userB, _ := routedHeaders(t, body("b-secret"), "client", chatPath, nil)
	noClientSecret, _ := routedHeaders(t, body("a-secret"), "", chatPath, nil)

	require.Equal(t, expectedPrefix("a-secret", head), userA.Get(cachePrefixHeader))
	require.NotEqual(t, userA.Get(cachePrefixHeader), userB.Get(cachePrefixHeader))
	require.Equal(t, userA.Get(cachePrefixHeader), noClientSecret.Get(cachePrefixHeader))
	for name, values := range userA {
		require.NotContains(t, strings.Join(values, " "), "a-secret", "%s leaked the secret", name)
	}
}

func TestRoutingHeadersLetCallerSetHeadersWin(t *testing.T) {
	headers, _ := routedHeaders(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, "s1", chatPath,
		map[string]string{modelHeader: "pinned", cachePrefixHeader: "pinned-prefix"})

	require.Equal(t, "pinned", headers.Get(modelHeader))
	require.Equal(t, "pinned-prefix", headers.Get(cachePrefixHeader))
}

func TestRoutingHeadersPreserveTheRequestTheyCannotRead(t *testing.T) {
	for _, body := range []string{"not json", "[1,2,3]"} {
		headers, forwarded := routedHeaders(t, body, "s1", chatPath, nil)
		require.Empty(t, headers.Get(modelHeader), body)
		require.Equal(t, body, forwarded, body)
	}

	noModel, _ := routedHeaders(t, `{"messages":[{"role":"user","content":"hi"}]}`, "s1", chatPath, nil)
	require.Empty(t, noModel.Get(modelHeader))
	require.NotEmpty(t, noModel.Get(cachePrefixHeader))

	// seed is int64-range: a layer that re-marshaled the body would corrupt it through float64.
	headers, forwarded := routedHeaders(t,
		`{"model":"m","seed":9007199254740993,"messages":[{"role":"user","content":"hi"}]}`,
		"s1", chatPath, map[string]string{"X-Source": "caller"})
	require.Contains(t, forwarded, `"seed":9007199254740993`)
	require.Equal(t, "caller", headers.Get("X-Source"))
}

func TestRoutingHeadersReplayTheBodyForRetriesBelow(t *testing.T) {
	// EHBP key rotation retries below this layer, reading the body a second time through GetBody.
	rt := &sealedBodyTransport{secret: "s1", routing: true, transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		sent, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		require.NotNil(t, req.GetBody)
		replay, err := req.GetBody()
		require.NoError(t, err)
		again, err := io.ReadAll(replay)
		require.NoError(t, err)
		require.Equal(t, string(sent), string(again))
		return newResponse(http.StatusOK, "ok"), nil
	})}
	_, err := rt.RoundTrip(postJSONRequest(t, "https://gateway.example.com"+chatPath,
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
}

// The routing headers are EHBP-only, and must see the body after the cache secret was injected into it.
func TestSealedRequestTransportLayering(t *testing.T) {
	var sealed *http.Request
	sealing := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		sealed = req
		return newResponse(http.StatusOK, "ok"), nil
	})
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`

	ehbp := sealedRequestTransport(sealing, TransportEHBP, "s1")
	_, err := ehbp.RoundTrip(postJSONRequest(t, "https://gateway.example.com"+chatPath, body))
	require.NoError(t, err)
	require.Equal(t, "m", sealed.Header.Get(modelHeader))
	require.NotEmpty(t, sealed.Header.Get(cachePrefixHeader))
	injected, err := io.ReadAll(sealed.Body)
	require.NoError(t, err)
	require.Contains(t, string(injected), `"user_cache_secret":"s1"`)

	tls := sealedRequestTransport(sealing, TransportTLS, "s1")
	_, err = tls.RoundTrip(postJSONRequest(t, "https://enclave.example.com"+chatPath, body))
	require.NoError(t, err)
	require.Empty(t, sealed.Header.Get(modelHeader))
	require.Empty(t, sealed.Header.Get(cachePrefixHeader))
}
