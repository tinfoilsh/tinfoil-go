package tinfoil

import (
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/internal/cachesecret"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
)

// NewCacheSecretTransport returns an http.RoundTripper that adds the
// user_cache_secret request-body member, which scopes Tinfoil's prompt cache,
// to the requests that the caller sends through it, exactly as a
// RouterHTTPClient or a GatewayHTTPClient adds it to its own requests, and
// then sends every request over next. It is for a client that reaches
// Tinfoil's router without a RouterHTTPClient, such as an EnclaveHTTPClient
// that is pointed at the router or a service that forwards raw OpenAI-style
// requests through one, since an EnclaveHTTPClient never adds the member by
// itself.
//
// An empty secret selects the random secret that is generated once per
// process and that every router and gateway client in the process shares, as
// an empty RouterOptions.UserCacheSecret does. The SDK never persists it, so
// a service that wants a stable scope across processes passes its own
// secret.
//
// Only a POST request with a body whose URL path ends in /chat/completions,
// /completions or /responses can carry the member; the transport sends every
// other request unchanged. It reads the whole body of such a request into
// memory, and when the body is one JSON object, it resolves the member in
// this order:
//
//  1. a non-empty string that the body already carries wins, and the body is
//     sent byte for byte as it is;
//  2. an empty string, or a body that lacks the member, gets secret;
//  3. any other value, such as null or a number, or a member that appears
//     more than once, belongs to the caller, and the body is sent as it is.
//
// A body that isn't one JSON object, such as a multipart form or invalid
// UTF-8, is also sent as it is. When the transport adds the member, it
// re-encodes the object, which may reorder its members but keeps every
// number's digits, and it sets the request's ContentLength, Content-Length
// header and GetBody for the new body, so that a layer below it that replays
// the request, such as the attested client's retry after a key rotation,
// sends the same bytes.
//
// Wrap the transport of an attested client, so that the member is added
// before the client seals the body (EHBP) or sends it over the pinned
// connection (TLS):
//
//	client, err := tinfoil.NewEnclaveHTTPClient(ctx, host, trust, opts)
//	// ...
//	client.Transport = tinfoil.NewCacheSecretTransport(client.Transport, secret)
//
// The transport only rewrites request bodies and calls next, so next keeps
// every protection that it applies: an attested client still refuses other
// origins, verifies the enclave and pins or seals each request. Wrapping a
// transport that isn't attested, such as http.DefaultTransport, sends the
// secret wherever that transport sends the request, so wrap only a transport
// whose requests reach Tinfoil's router. A nil next uses
// http.DefaultTransport, as http.Client does. A RouterHTTPClient and a
// GatewayHTTPClient already add the member, so they need no wrapping. An
// OpenAIClient sends through the attested client's own chain, not through
// the Transport field of its embedded *http.Client, so with an OpenAIClient
// over an EnclaveHTTPClient, set the member in each request instead, for
// example with option.WithJSONSet.
func NewCacheSecretTransport(next http.RoundTripper, secret string) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return transport.WithCacheSecret(next, cachesecret.Resolve(secret))
}
