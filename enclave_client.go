package tinfoil

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Binding selects how traffic is tied to the keys an enclave attests. The
// zero value selects the route's default.
type Binding string

const (
	// BindingTLS pins each connection to the attested TLS key. It protects the
	// whole request and response, and needs a direct connection.
	BindingTLS Binding = "tls"
	// BindingEHBP seals request and response bodies to the attested HPKE key,
	// so they stay private through a proxy. Requests without a body aren't
	// sealed.
	BindingEHBP Binding = "ehbp"
)

func (b Binding) enclaveBinding(routeDefault enclave.Binding) (enclave.Binding, error) {
	switch b {
	case "":
		return routeDefault, nil
	case BindingTLS:
		return enclave.TLS, nil
	case BindingEHBP:
		return enclave.EHBP, nil
	}
	return nil, &ConfigurationError{Err: fmt.Errorf("unknown binding %q", b)}
}

// EnclaveOptions configures an EnclaveHTTPClient.
type EnclaveOptions struct {
	// Binding defaults to BindingTLS for NewEnclaveHTTPClient and to BindingEHBP
	// for DiscoverRouter.
	Binding Binding
	// BaseURL is a path on the enclave's own HTTPS origin, or an HTTPS proxy on
	// another origin, which requires BindingEHBP. Requests to a proxy carry
	// X-Tinfoil-Enclave-Url so it can forward them to the enclave.
	BaseURL string
	// Verifier is the verification policy; nil selects the defaults.
	Verifier *verify.Verifier
	// UserCacheSecret is the default prompt-cache scope for the client's
	// requests; empty resolves it from TINFOIL_USER_CACHE_SECRET or
	// ~/.tinfoil/user_cache_secret. A non-empty user_cache_secret string in a
	// request's JSON body overrides it, so a server can scope the cache to each
	// end user, for example with option.WithJSONSet("user_cache_secret", s).
	UserCacheSecret string
}

// EnclaveHTTPClient is an *http.Client whose requests reach only one attested
// enclave.
type EnclaveHTTPClient struct {
	*http.Client
	handle *enclave.Handle
	// secure is the client OpenAI clients use, which changes to the embedded
	// client can't reach.
	secure             *http.Client
	baseURL, openAIURL string
}

// NewEnclaveHTTPClient verifies the enclave at host against repo,
// owner/name[@tag][@sha256:digest]. An empty repo leaves config
// authorization to opts.Verifier.
func NewEnclaveHTTPClient(host, repo string, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	if host == "" {
		return nil, &ConfigurationError{Err: errors.New("enclave host is required")}
	}
	if opts == nil {
		opts = &EnclaveOptions{}
	}
	binding, err := opts.Binding.enclaveBinding(enclave.TLS)
	if err != nil {
		return nil, err
	}
	if opts.BaseURL != "" {
		if err := validateBaseURL(opts.BaseURL); err != nil {
			return nil, err
		}
	}
	if binding == enclave.TLS {
		if err := transport.ValidateTLSBaseURL(opts.BaseURL, host); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	}
	handle, err := enclave.NewHandleWithVerifier(host, repo, opts.Verifier)
	if err != nil {
		return nil, err
	}
	return newEnclaveHTTPClient(handle, binding, opts)
}

// DiscoverRouter returns a client for the first router from Tinfoil's router
// list that passes verification, and otherwise for inference.tinfoil.sh. It
// does network I/O, and calling it again discovers again. It exists only
// while the router is Tinfoil's default route.
func DiscoverRouter(ctx context.Context, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	if opts == nil {
		opts = &EnclaveOptions{}
	}
	binding, err := opts.Binding.enclaveBinding(enclave.EHBP)
	if err != nil {
		return nil, err
	}
	if opts.BaseURL != "" {
		if err := validateBaseURL(opts.BaseURL); err != nil {
			return nil, err
		}
	}
	handle, err := enclave.DiscoverRouter(ctx, opts.Verifier)
	if err != nil {
		return nil, err
	}
	return newEnclaveHTTPClient(handle, binding, opts)
}

func newEnclaveHTTPClient(handle *enclave.Handle, binding enclave.Binding, opts *EnclaveOptions) (*EnclaveHTTPClient, error) {
	secure, err := secureHTTPClient(handle, binding, opts.BaseURL,
		transport.ResolveUserCacheSecret(opts.UserCacheSecret, opts.UserCacheSecret != ""))
	if err != nil {
		return nil, err
	}
	return &EnclaveHTTPClient{
		Client:    &http.Client{Transport: secure.Transport},
		handle:    handle,
		secure:    secure,
		baseURL:   cmp.Or(opts.BaseURL, "https://"+handle.Enclave()+"/"),
		openAIURL: cmp.Or(opts.BaseURL, "https://"+handle.Enclave()+"/v1/"),
	}, nil
}

// BaseURL returns the URL requests are sent to: EnclaveOptions.BaseURL, or the
// enclave's own origin.
func (c *EnclaveHTTPClient) BaseURL() string {
	return c.baseURL
}

// EnsureVerified returns a verification that is valid now, verifying first
// only if the cached one has expired or been rejected.
func (c *EnclaveHTTPClient) EnsureVerified(ctx context.Context) (*verify.Verification, error) {
	return c.handle.EnsureVerified(ctx)
}

// Reverify verifies again even if the cached verification is still valid.
func (c *EnclaveHTTPClient) Reverify(ctx context.Context) (*verify.Verification, error) {
	return c.handle.Reverify(ctx)
}

// Current returns the last successful verification without checking it. It
// may have expired or been rejected; use EnsureVerified for one that is
// valid.
func (c *EnclaveHTTPClient) Current() *verify.Verification {
	return c.handle.Verification()
}
