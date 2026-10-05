// Package mobile is the SDK's gomobile surface: the one package bound into
// Tinfoil.xcframework.
//
// It exists so the Go API does not have to be FFI-shaped. gomobile silently
// drops anything it cannot represent — maps, slices other than []byte, struct
// values, and every type from an unbound package, which includes time.Time and
// context.Context — so a package that is both a Go API and a binding target
// ends up serving neither well. Everything structured therefore crosses as
// JSON, and the shape of that JSON is declared in verification.go rather than
// inherited from whatever the SDK's types happen to look like.
package mobile

import (
	"encoding/json"

	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Client verifies an enclave and reports what it proved. It wraps the SDK's
// own client, which is not itself bound.
type Client struct {
	inner *enclave.Handle
}

// NewClient verifies the enclave at host against repo, a trusted
// owner/name[@tag][@sha256:digest] reference, using the default policy.
func NewClient(host, repo string) (*Client, error) {
	inner, err := enclave.NewHandle(host, repo, nil)
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner}, nil
}

// NewClientWithOptions is NewClient with options, as the JSON object
// enclave.Options describes: pinned registers, a freshness bound in integer
// nanoseconds, and the identity of the SDK built on this one, such as
// {"name":"tinfoil-swift","version":"0.8.2"}. An empty string selects the
// defaults.
func NewClientWithOptions(host, repo, optionsJSON string) (*Client, error) {
	opts, err := parseOptions(optionsJSON)
	if err != nil {
		return nil, err
	}
	inner, err := enclave.NewHandle(host, repo, opts)
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner}, nil
}

// NewDefaultClient discovers Tinfoil's routers and returns a client for the
// first that verifies against tinfoilsh/confidential-model-router, falling back
// to inference.tinfoil.sh. optionsJSON is as for NewClientWithOptions and
// applies to every router tried.
//
// Discovery verifies the router it selects, so Verification already holds the
// result. The fallback is returned unverified: Verification is empty and the
// first Verify contacts it.
func NewDefaultClient(optionsJSON string) (*Client, error) {
	opts, err := parseOptions(optionsJSON)
	if err != nil {
		return nil, err
	}
	inner, err := enclave.NewDefaultHandle(opts)
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner}, nil
}

// parseOptions decodes the options JSON, where an empty string selects the
// defaults.
func parseOptions(optionsJSON string) (*enclave.Options, error) {
	if optionsJSON == "" {
		return nil, nil
	}
	return enclave.ParseOptionsJSON(optionsJSON)
}

// ViaRelay returns a client for the same enclave, repository and options that
// fetches attestation through relay, a host with an optional port, which
// forwards it to the enclave. The relay is reached over HTTPS. The new client
// shares no verification with this one and verifies on first use.
func (c *Client) ViaRelay(relay string) *Client {
	return &Client{inner: c.inner.ViaRelay(relay)}
}

// Enclave returns the host this client verifies.
func (c *Client) Enclave() string { return c.inner.Enclave() }

// Repo returns the trusted repository reference, including any pins.
func (c *Client) Repo() string { return c.inner.Repo() }

// Verify re-verifies the enclave and returns what the document proved, as the
// JSON described in verification.go.
func (c *Client) Verify() (string, error) {
	verified, err := c.inner.Verify()
	if err != nil {
		return "", err
	}
	return encode(verified, c.inner.Enclave())
}

// Verification returns the last successful verification without re-verifying,
// or an empty string if this client has not verified yet.
func (c *Client) Verification() (string, error) {
	verified := c.inner.Verification()
	if verified == nil {
		return "", nil
	}
	return encode(verified, c.inner.Enclave())
}

// Response is the result of Request.
type Response struct {
	StatusCode int
	Body       []byte
}

// Request sends an HTTPS request whose connection is pinned to the verified
// TLS key, verifying first if the client holds no current verification.
// url is absolute or a path on the enclave, headersJSON is a JSON object of
// header names to values or empty, and the whole response body is read. A
// failure of the HTTP client itself, such as a refused connection, has no
// category prefix.
func (c *Client) Request(method, url, headersJSON string, body []byte) (*Response, error) {
	resp, err := c.inner.Request(method, url, headersJSON, body)
	if err != nil {
		return nil, err
	}
	return &Response{StatusCode: resp.StatusCode, Body: resp.Body}, nil
}

func encode(verified *verify.Verification, enclave string) (string, error) {
	encoded, err := json.Marshal(toVerificationJSON(verified, enclave))
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
