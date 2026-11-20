package tinfoil

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
)

// EnclaveOpenAIClient is an OpenAI client whose requests go through an
// EnclaveHTTPClient. Its base URL is v1/ under the EHBP ProxyURL or, when there
// is none, under the enclave's origin. An option.WithBaseURL among its OpenAI
// options replaces that path, and must stay on the same origin. A per-request
// option.WithHTTPClient bypasses the enclave client and its protections.
type EnclaveOpenAIClient struct {
	*openai.Client
	httpClient *EnclaveHTTPClient
}

// NewEnclaveOpenAIClient creates an EnclaveHTTPClient as NewEnclaveHTTPClient
// does, and an OpenAI client over it. It applies openaiOpts after the default
// base URL, then sets the HTTP client so that openaiOpts can't replace it. A
// base URL from openaiOpts on another origin than the default is an
// ErrConfiguration error, reported before any network I/O.
func NewEnclaveOpenAIClient(ctx context.Context, host string, trust Trust, opts *EnclaveOptions, openaiOpts ...option.RequestOption) (*EnclaveOpenAIClient, error) {
	c, err := unverifiedEnclaveHTTPClient(host, trust, opts)
	if err != nil {
		return nil, err
	}
	oc, err := newEnclaveOpenAIClient(c, openaiOpts)
	if err != nil {
		return nil, err
	}
	if _, err := c.EnsureVerified(ctx); err != nil {
		return nil, err
	}
	return oc, nil
}

func newEnclaveOpenAIClient(c *EnclaveHTTPClient, opts []option.RequestOption) (*EnclaveOpenAIClient, error) {
	client, _, err := newOpenAIClient(c.secure, c.openAIURL, opts)
	if err != nil {
		return nil, err
	}
	return &EnclaveOpenAIClient{Client: client, httpClient: c}, nil
}

// HTTPClient returns the enclave client the OpenAI client sends through.
func (c *EnclaveOpenAIClient) HTTPClient() *EnclaveHTTPClient {
	return c.httpClient
}

// RouterOpenAIClient is an OpenAI client whose requests go through a
// RouterHTTPClient. Its base URL is v1/ under the EHBP ProxyURL or, when there
// is none, under the router's origin. An option.WithBaseURL among its OpenAI
// options replaces that path, and must stay on the same origin. A per-request
// option.WithHTTPClient bypasses the router client and its protections.
type RouterOpenAIClient struct {
	*openai.Client
	httpClient *RouterHTTPClient
	baseURL    string
}

// NewRouterOpenAIClient creates a RouterHTTPClient as NewRouterHTTPClient
// does, and an OpenAI client over it. It applies openaiOpts after the default
// base URL, then sets the HTTP client so that openaiOpts can't replace it. A
// base URL from openaiOpts on another origin than the default is an
// ErrConfiguration error. It is reported before any network I/O when the
// client uses a ProxyURL; otherwise the router's origin is known only after
// discovery, so it is reported then.
func NewRouterOpenAIClient(ctx context.Context, opts *RouterOptions, openaiOpts ...option.RequestOption) (*RouterOpenAIClient, error) {
	c, err := newRouterHTTPClient(ctx, opts, func(proxyURL string) error {
		if proxyURL != "" {
			_, err := checkOpenAIBaseURL(openAIURL(proxyURL), openaiOpts)
			return err
		}
		// The router's origin is known only after discovery, but a base URL
		// that can't be on any router's origin fails now.
		baseURL, err := resolveOpenAIBaseURL("https://router.invalid/v1/", openaiOpts)
		if err != nil {
			return err
		}
		origin, err := transport.OriginOf(baseURL)
		if err != nil {
			return errs.Configuration(fmt.Errorf("invalid OpenAI base URL: %w", err))
		}
		if !strings.HasPrefix(origin, "https://") {
			return errs.Configuration(fmt.Errorf("invalid OpenAI base URL: its origin %q isn't the router's HTTPS origin", origin))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return newRouterOpenAIClient(c, openaiOpts)
}

func newRouterOpenAIClient(c *RouterHTTPClient, opts []option.RequestOption) (*RouterOpenAIClient, error) {
	client, baseURL, err := newOpenAIClient(c.secure, c.openAIURL, opts)
	if err != nil {
		return nil, err
	}
	return &RouterOpenAIClient{Client: client, httpClient: c, baseURL: baseURL}, nil
}

// HTTPClient returns the router client the OpenAI client sends through.
func (c *RouterOpenAIClient) HTTPClient() *RouterHTTPClient {
	return c.httpClient
}

// GatewayOpenAIClient is an OpenAI client whose requests go through a
// GatewayHTTPClient. Its base URL is the gateway's URL. An option.WithBaseURL
// among its OpenAI options replaces it, and must stay on the gateway's origin.
// A per-request option.WithHTTPClient bypasses the gateway client and its
// protections.
type GatewayOpenAIClient struct {
	*openai.Client
	httpClient *GatewayHTTPClient
}

// NewGatewayOpenAIClient creates a GatewayHTTPClient as NewGatewayHTTPClient
// does, and an OpenAI client over it. It applies openaiOpts after the default
// base URL, then sets the HTTP client so that openaiOpts can't replace it. A
// base URL from openaiOpts on another origin than the gateway's is an
// ErrConfiguration error, reported before any network I/O.
//
// Experimental: the gateway route is new, and this API may change or be
// removed in a later release.
func NewGatewayOpenAIClient(ctx context.Context, opts *GatewayOptions, openaiOpts ...option.RequestOption) (*GatewayOpenAIClient, error) {
	c, err := unverifiedGatewayHTTPClient(opts)
	if err != nil {
		return nil, err
	}
	client, _, err := newOpenAIClient(c.secure, c.baseURL, openaiOpts)
	if err != nil {
		return nil, err
	}
	if _, err := c.transport.Models(ctx); err != nil {
		return nil, err
	}
	return &GatewayOpenAIClient{Client: client, httpClient: c}, nil
}

// HTTPClient returns the gateway client the OpenAI client sends through.
func (c *GatewayOpenAIClient) HTTPClient() *GatewayHTTPClient {
	return c.httpClient
}

// openAIURL returns the default OpenAI base URL: v1/ under base, which is a
// proxy URL or an origin, whether or not base ends with a slash.
func openAIURL(base string) string {
	return strings.TrimSuffix(base, "/") + "/v1/"
}

// newOpenAIClient returns an OpenAI client that sends through httpClient, and
// the base URL that it sends to, which checkOpenAIBaseURL returns. It applies
// the default base URL first so that opts can replace it, and the HTTP client
// last so that they can't.
func newOpenAIClient(httpClient option.HTTPClient, defaultURL string, opts []option.RequestOption) (*openai.Client, string, error) {
	baseURL, err := checkOpenAIBaseURL(defaultURL, opts)
	if err != nil {
		return nil, "", err
	}
	client := openai.NewClient(slices.Concat(
		[]option.RequestOption{option.WithBaseURL(defaultURL)},
		opts,
		[]option.RequestOption{option.WithHTTPClient(httpClient)},
	)...)
	return &client, baseURL, nil
}

// checkOpenAIBaseURL returns the base URL that an OpenAI client sends to when
// it applies opts after defaultURL: defaultURL, or a base URL from opts on the
// same origin. A base URL on another origin is an ErrConfiguration error.
func checkOpenAIBaseURL(defaultURL string, opts []option.RequestOption) (string, error) {
	baseURL, err := resolveOpenAIBaseURL(defaultURL, opts)
	if err != nil {
		return "", err
	}
	defaultOrigin, err := transport.OriginOf(defaultURL)
	if err != nil {
		return "", errs.Configuration(fmt.Errorf("invalid default base URL: %w", err))
	}
	origin, err := transport.OriginOf(baseURL)
	if err != nil {
		return "", errs.Configuration(fmt.Errorf("invalid OpenAI base URL: %w", err))
	}
	if origin != defaultOrigin {
		return "", errs.Configuration(fmt.Errorf("invalid OpenAI base URL: its origin %q isn't the client's origin %q; the base URL may change only the path", origin, defaultOrigin))
	}
	return baseURL, nil
}

// errBaseURLRead stops the request that resolveOpenAIBaseURL makes once it has
// read the request's URL.
var errBaseURLRead = errors.New("base URL read")

// resolveOpenAIBaseURL returns the base URL that an OpenAI client sends to when
// it applies opts after defaultURL. openai-go doesn't expose the options that
// it resolves, so it builds such a client and reads the URL of a request to
// the base URL itself. The middleware that reads it is the first one, so the
// request stops there: neither the caller's middleware nor any HTTP client
// runs, and no network I/O happens. An error from opts is an ErrConfiguration
// error, since it would fail every request.
func resolveOpenAIBaseURL(defaultURL string, opts []option.RequestOption) (string, error) {
	var baseURL string
	read := func(req *http.Request, _ option.MiddlewareNext) (*http.Response, error) {
		u := *req.URL
		u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = "", false, "", ""
		baseURL = u.String()
		return nil, errBaseURLRead
	}
	probe := openai.NewClient(slices.Concat(
		[]option.RequestOption{option.WithMiddleware(read), option.WithBaseURL(defaultURL)},
		opts,
		[]option.RequestOption{option.WithHTTPClient(noNetwork{}), option.WithMaxRetries(0)},
	)...)
	err := probe.Get(context.Background(), "", nil, nil)
	if !errors.Is(err, errBaseURLRead) {
		if err == nil {
			err = errors.New("the request sent no URL")
		}
		return "", errs.Configuration(fmt.Errorf("invalid OpenAI options: %w", err))
	}
	return baseURL, nil
}

// noNetwork is the HTTP client of resolveOpenAIBaseURL's request, which fails
// any request that reaches it.
type noNetwork struct{}

func (noNetwork) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("resolving the base URL sends no requests")
}
