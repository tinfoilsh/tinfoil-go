package tinfoil

import (
	"errors"
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

// WithAPIPath sets the path of the OpenAI API, which NewOpenAIClient joins
// under the HTTP client's BaseURL: the EHBP ProxyURL or, when there is none,
// the enclave's origin, or the gateway's URL. Without it, the path is "/v1/".
// It must be an absolute path that consists only of RFC 3986 path characters,
// without a query, a fragment, an encoded slash or backslash, or a "." or ".."
// segment, percent-encoded or not; anything else, the empty string included,
// is an ErrConfiguration error from NewOpenAIClient.
//
// It is an option of NewOpenAIClient and NewClient, which take it among their
// openai-go options and don't pass it on to openai-go. When it is given more
// than once, each must be valid and the last one wins. It configures the
// client, not a request: passed to a request method, it fails that request
// with an ErrConfiguration error before anything is sent.
func WithAPIPath(path string) option.RequestOption {
	return apiPathOption{RequestOption: refusePerRequest, path: path}
}

// apiPathOption is the option that WithAPIPath returns. NewOpenAIClient takes
// it out of its options; openai-go applies it only when it is passed to a
// request, and its Apply method, refusePerRequest's, then fails.
type apiPathOption struct {
	option.RequestOption
	path string
}

// refusePerRequest is an option.RequestOption whose Apply method fails.
var refusePerRequest = refusalFor(option.RequestOption.Apply, errs.Configuration(errors.New(
	"tinfoil.WithAPIPath configures the client, not a request: pass it to tinfoil.NewOpenAIClient")))

// refusal is a request option whose Apply method returns err. C is the
// parameter of option.RequestOption's Apply method, a type that openai-go
// declares in an internal package, so that this package can't name it.
type refusal[C any] struct{ err error }

func (r refusal[C]) Apply(C) error { return r.err }

// refusalFor returns a refusal of err for the option interface whose Apply
// method apply is, inferring C from it. The method sets of refusal[C] and the
// interface then match, which the compiler can't see inside a generic
// function, so the conversion to the interface is checked at run time.
func refusalFor[C any](apply func(option.RequestOption, C) error, err error) option.RequestOption {
	return any(refusal[C]{err}).(option.RequestOption)
}

// OpenAIClient is an OpenAI client whose requests go through an
// AttestedHTTPClient. A per-request option.WithHTTPClient bypasses the
// attested client and its protections. A per-request option.WithBaseURL
// replaces the base URL for that request, and the attested client refuses one
// on another origin. A per-request WithAPIPath fails the request.
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
// The base URL is the API path, "/v1/" unless a WithAPIPath among opts sets
// it, joined under hc.BaseURL(), whatever the route. The client takes its own
// options, such as WithAPIPath, out of opts and applies the rest, which are
// openai-go's, then sets the HTTP client and the base URL so that they can't
// replace them. An option.WithBaseURL among opts, OPENAI_BASE_URL in the
// environment, and a data residency option have no effect; use WithAPIPath to
// change the API path.
func NewOpenAIClient(hc AttestedHTTPClient, opts ...option.RequestOption) (*OpenAIClient, error) {
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
	apiPath, openaiOpts, err := splitOptions(opts)
	if err != nil {
		return nil, err
	}
	baseURL := joinAPIPath(root, apiPath)
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

// splitOptions takes the client's own options out of opts: it returns the
// API path that the last WithAPIPath sets, or defaultAPIPath without one,
// and the other options, which are openai-go's. Every WithAPIPath must be
// valid.
func splitOptions(opts []option.RequestOption) (apiPath string, openaiOpts []option.RequestOption, err error) {
	apiPath = defaultAPIPath
	openaiOpts = make([]option.RequestOption, 0, len(opts))
	for _, opt := range opts {
		if o, ok := opt.(apiPathOption); ok {
			if err := validateAPIPath(o.path); err != nil {
				return "", nil, err
			}
			apiPath = o.path
			continue
		}
		openaiOpts = append(openaiOpts, opt)
	}
	return apiPath, openaiOpts, nil
}

// defaultAPIPath is the API path of an OpenAIClient without WithAPIPath.
const defaultAPIPath = "/v1/"

// joinAPIPath returns apiPath, which validateAPIPath accepted, joined under
// root, a proxy URL, an origin or a gateway URL, whether or not root ends
// with a slash. The result ends with a slash, so that request paths join
// under it.
func joinAPIPath(root, apiPath string) string {
	return withTrailingSlash(strings.TrimSuffix(root, "/") + apiPath)
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
