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

// OpenAIOptions configures an OpenAIClient.
type OpenAIOptions struct {
	// APIPath is the path of the OpenAI API, joined under the EHBP ProxyURL
	// or, when there is none, under the enclave's origin. Empty selects
	// "/v1/". It must be an absolute path, without a query, a fragment, an
	// encoded slash, or a "." or ".." segment, percent-encoded or not. A gateway client's URL already carries the API
	// path, so a non-empty APIPath with one is an ErrConfiguration error.
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
// The client applies openaiOpts, then sets the HTTP client and the base URL
// so that openaiOpts can't replace them. An option.WithBaseURL among
// openaiOpts, OPENAI_BASE_URL in the environment, and a data residency option
// have no effect; set opts.APIPath to change the API path.
func NewOpenAIClient(hc AttestedHTTPClient, opts *OpenAIOptions, openaiOpts ...option.RequestOption) (*OpenAIClient, error) {
	if opts == nil {
		opts = &OpenAIOptions{}
	}
	var (
		secure  *http.Client
		baseURL string
		err     error
	)
	switch c := hc.(type) {
	case *EnclaveHTTPClient:
		if c != nil && c.secure != nil {
			secure = c.secure
			baseURL, err = joinAPIPath(c.baseURL, opts.APIPath)
		}
	case *RouterHTTPClient:
		if c != nil && c.secure != nil {
			secure = c.secure
			baseURL, err = joinAPIPath(c.baseURL, opts.APIPath)
		}
	case *GatewayHTTPClient:
		if c != nil && c.secure != nil {
			// The gateway URL carries no query or fragment, so a slash can end
			// it, as option.WithBaseURL would end its path.
			secure, baseURL = c.secure, withTrailingSlash(c.baseURL)
			if opts.APIPath != "" {
				err = errs.Configuration(errors.New("invalid API path: a gateway client's URL already carries the API path; set GatewayOptions.URL instead"))
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if secure == nil {
		return nil, errs.Configuration(fmt.Errorf("the HTTP client must be an *EnclaveHTTPClient, *RouterHTTPClient or *GatewayHTTPClient from its constructor, not %T", hc))
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
// under root, a proxy URL or an origin, whether or not root ends with a slash.
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

// validateAPIPath requires an absolute path without a query, a fragment, or a
// "." or ".." segment, percent-encoded or not, so that it can only name a path
// under its root.
func validateAPIPath(apiPath string) error {
	if !strings.HasPrefix(apiPath, "/") || strings.HasPrefix(apiPath, "//") {
		return errs.Configuration(fmt.Errorf("invalid API path %q: it must be an absolute path, such as /v1/", apiPath))
	}
	if strings.ContainsAny(apiPath, "?#") {
		return errs.Configuration(fmt.Errorf("invalid API path %q: it must not carry a query or a fragment", apiPath))
	}
	for _, segment := range strings.Split(apiPath, "/") {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return errs.Configuration(fmt.Errorf("invalid API path %q: %w", apiPath, err))
		}
		if decoded == "." || decoded == ".." || strings.Contains(decoded, "/") {
			return errs.Configuration(fmt.Errorf("invalid API path %q: it must not contain a \".\" or \"..\" segment or an encoded slash", apiPath))
		}
	}
	return nil
}
