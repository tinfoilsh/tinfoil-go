package tinfoil

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

// AttestedHTTPClient is an HTTP client that an OpenAIClient can send through:
// an *EnclaveHTTPClient, a *RouterHTTPClient or a *GatewayHTTPClient. Its
// unexported method keeps other packages from implementing it. Type-assert to
// the concrete type for its own methods.
type AttestedHTTPClient interface {
	// Do sends a request through the client, as http.Client.Do does.
	Do(req *http.Request) (*http.Response, error)
	// BaseURL returns where the client sends requests.
	BaseURL() string
	attestedHTTPClient()
}

func (*EnclaveHTTPClient) attestedHTTPClient() {}
func (*RouterHTTPClient) attestedHTTPClient()  {}
func (*GatewayHTTPClient) attestedHTTPClient() {}

// OpenAIOptions configures an OpenAIClient.
type OpenAIOptions struct {
	// APIPath is the path of the OpenAI API, joined under the HTTP client's
	// BaseURL: the EHBP ProxyURL or, when there is none, the enclave's
	// origin, or the gateway's URL. Empty selects "/v1/". It must be an
	// absolute path that consists only of RFC 3986 path characters, without a
	// query, a fragment, an encoded slash or backslash, or a "." or ".."
	// segment, percent-encoded or not.
	APIPath string
}

// OpenAIClient is an OpenAI client whose requests go through an
// AttestedHTTPClient. A per-request option.WithHTTPClient bypasses the
// attested client and its protections. A per-request option.WithBaseURL
// replaces the base URL for that request, and the attested client refuses one
// on another origin.
type OpenAIClient struct {
	*openai.Client
	httpClient AttestedHTTPClient
	baseURL    string
}

// NewOpenAIClient returns an OpenAI client that sends through hc, which must
// be an *EnclaveHTTPClient, a *RouterHTTPClient or a *GatewayHTTPClient that
// its constructor returned; anything else, nil included, is an
// ErrConfiguration error. It does no network I/O: hc was verified when it was
// created and verifies again by itself.
//
// The base URL is opts.APIPath joined under hc.BaseURL(), whatever the
// route. The client applies openaiOpts, then sets the HTTP client and the
// base URL so that openaiOpts can't replace them. An option.WithBaseURL among
// openaiOpts, OPENAI_BASE_URL in the environment, and a data residency option
// have no effect; set opts.APIPath to change the API path.
func NewOpenAIClient(hc AttestedHTTPClient, opts *OpenAIOptions, openaiOpts ...option.RequestOption) (*OpenAIClient, error) {
	if opts == nil {
		opts = &OpenAIOptions{}
	}
	var secure *http.Client
	var root string
	switch c := hc.(type) {
	case *EnclaveHTTPClient:
		if c != nil {
			secure, root = c.secure, c.baseURL
		}
	case *RouterHTTPClient:
		if c != nil {
			secure, root = c.secure, c.baseURL
		}
	case *GatewayHTTPClient:
		if c != nil {
			secure, root = c.secure, c.baseURL
		}
	}
	if secure == nil {
		return nil, errs.Configuration(fmt.Errorf("the HTTP client must be an *EnclaveHTTPClient, *RouterHTTPClient or *GatewayHTTPClient from its constructor, not %T", hc))
	}
	baseURL, err := joinAPIPath(root, opts.APIPath)
	if err != nil {
		return nil, err
	}
	// openai-go refuses a base URL and a data residency option in the same
	// call, so the caller's options go in an inner client's call, whose
	// Options the outer call applies before the HTTP client and base URL.
	inner := openai.NewClient(openaiOpts...)
	client := openai.NewClient(slices.Concat(inner.Options, []option.RequestOption{
		option.WithHTTPClient(secure),
		option.WithBaseURL(baseURL),
	})...)
	return &OpenAIClient{Client: &client, httpClient: hc, baseURL: baseURL}, nil
}

// HTTPClient returns the attested client that the OpenAI client sends
// through.
func (c *OpenAIClient) HTTPClient() AttestedHTTPClient {
	return c.httpClient
}

// BaseURL returns the OpenAI base URL that the client sends requests to.
func (c *OpenAIClient) BaseURL() string {
	return c.baseURL
}

// defaultAPIPath is the API path of an OpenAIOptions without one.
const defaultAPIPath = "/v1/"

// joinAPIPath returns apiPath, or defaultAPIPath when it is empty, joined
// under root, a proxy URL, an origin or a gateway URL, whether or not root
// ends with a slash.
// The result ends with a slash, so that request paths join under it.
func joinAPIPath(root, apiPath string) (string, error) {
	if apiPath == "" {
		apiPath = defaultAPIPath
	}
	if err := validateAPIPath(apiPath); err != nil {
		return "", err
	}
	return withTrailingSlash(strings.TrimSuffix(root, "/") + apiPath), nil
}

// withTrailingSlash returns u ending with a slash, so that request paths join
// under it.
func withTrailingSlash(u string) string {
	if strings.HasSuffix(u, "/") {
		return u
	}
	return u + "/"
}

// isPathChar reports whether c is a character that a path may hold as it is
// written in a URL: RFC 3986 pchar, which includes the "%" of an escape, or
// "/". A URL parser could rewrite anything else, such as a backslash, a space
// or a control character, and turn it into a separator or a dot segment.
func isPathChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~!$&'()*+,;=:@%/", c) >= 0
}

// validateAPIPath requires an absolute path of RFC 3986 path characters
// without a query, a fragment, an encoded slash or backslash, or a "." or ".."
// segment, percent-encoded or not, so that it can only name a path under its
// root, and so that every URL parser reads it as it is written.
func validateAPIPath(apiPath string) error {
	if !strings.HasPrefix(apiPath, "/") || strings.HasPrefix(apiPath, "//") {
		return errs.Configuration(fmt.Errorf("invalid API path %q: it must be an absolute path, such as /v1/", apiPath))
	}
	if strings.ContainsAny(apiPath, "?#") {
		return errs.Configuration(fmt.Errorf("invalid API path %q: it must not carry a query or a fragment", apiPath))
	}
	for i := 0; i < len(apiPath); i++ {
		if !isPathChar(apiPath[i]) {
			return errs.Configuration(fmt.Errorf("invalid API path %q: it must consist only of RFC 3986 path characters", apiPath))
		}
	}
	for _, segment := range strings.Split(apiPath, "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return errs.Configuration(fmt.Errorf("invalid API path %q: %w", apiPath, err))
		}
		if decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "/\\") {
			return errs.Configuration(fmt.Errorf("invalid API path %q: it must not contain a \".\" or \"..\" segment or an encoded slash or backslash", apiPath))
		}
	}
	return nil
}
