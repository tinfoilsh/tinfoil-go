package tinfoil

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const defaultGatewayURL = "https://inference-gateway.tinfoil.sh/v1/"

// Gateway is an OpenAI client that seals each request to a verified replica
// of the model it names.
//
// Deprecated: use NewGatewayClient and GatewayClient.OpenAI.
type Gateway struct {
	*openai.Client
	httpClient *http.Client
	seal       *transport.Gateway
}

// GatewayOptions configures NewGatewayClient, and NewGateway through
// ClientOptions, ModelPins and PinnedModelsOnly.
type GatewayOptions struct {
	// Routing overrides and non-EHBP transports are rejected.
	//
	// Deprecated: NewGatewayClient takes Verifier and UserCacheSecret, and
	// GatewayClient.OpenAI takes OpenAI options.
	ClientOptions []ClientOption
	ModelPins     map[string]ModelPin
	// Requires at least one pin.
	PinnedModelsOnly bool

	// Verifier is the policy for unpinned models; nil selects the defaults.
	// NewGateway rejects it, as it does the other fields below.
	Verifier *verify.Verifier
	// UserCacheSecret scopes the prompt cache; empty resolves it from
	// TINFOIL_USER_CACHE_SECRET or ~/.tinfoil/user_cache_secret.
	UserCacheSecret string
	// URL is the gateway's base URL; empty selects Tinfoil's gateway.
	URL string
	// Catalog is read on every request and must return an immutable map safe
	// for concurrent readers; nil fetches the gateway's catalog once.
	Catalog func() Catalog
}

// ModelPin pins a model to tinfoilsh/name[@tag][@sha256:digest].
type ModelPin struct {
	Repo string
	// Verification is the pin's policy for NewGateway: nil inherits the
	// gateway defaults; non-nil replaces them, and a zero FreshnessMaxAge in a
	// replacement uses the SDK's seven-day default.
	//
	// Deprecated: NewGatewayClient takes Verifier.
	Verification *enclave.Options
	// Verifier is the pin's policy for NewGatewayClient: nil inherits
	// GatewayOptions.Verifier; non-nil replaces it. NewGateway rejects it.
	Verifier *verify.Verifier
}

// NewGateway copies opts and reads catalog on every request; nil fetches it once.
// Catalog callbacks must return immutable maps safe for concurrent readers.
// Replicas are verified on first use.
//
// Deprecated: use NewGatewayClient and GatewayClient.OpenAI.
func NewGateway(baseURL string, catalog func() Catalog, opts GatewayOptions) (*Gateway, error) {
	cfg := &clientConfig{}
	for _, opt := range opts.ClientOptions {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.enclave != "" || cfg.repo != "" || cmp.Or(cfg.transport, TransportEHBP) != TransportEHBP || cfg.baseURLSet {
		return nil, &ConfigurationError{Err: fmt.Errorf("a gateway takes its enclaves and repositories from its catalog and uses the EHBP transport")}
	}
	if opts.Verifier != nil || opts.UserCacheSecret != "" || opts.URL != "" || opts.Catalog != nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("the Verifier, UserCacheSecret, URL and Catalog options require NewGatewayClient")}
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway base URL must be an absolute HTTPS URL: %q", baseURL)}
	}
	if cfg.verification.EmbeddedConfig != nil || cfg.verification.ConfigAuthorizer != nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("caller-authorized config requires a direct enclave client")}
	}
	defaults, err := cfg.verification.Verifier()
	if err != nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway verification options: %w", err)}
	}
	pins := make(map[string]transport.ModelPin, len(opts.ModelPins))
	for model, pin := range opts.ModelPins {
		if pin.Verifier != nil {
			return nil, &ConfigurationError{Err: fmt.Errorf("model %q: ModelPin.Verifier requires NewGatewayClient", model)}
		}
		verifier := defaults
		if pin.Verification != nil {
			if pin.Verification.EmbeddedConfig != nil || pin.Verification.ConfigAuthorizer != nil {
				return nil, &ConfigurationError{Err: fmt.Errorf("model %q: caller-authorized config requires an enclave", model)}
			}
			if verifier, err = pin.Verification.Verifier(); err != nil {
				return nil, &ConfigurationError{Err: fmt.Errorf("model %q: %w", model, err)}
			}
		}
		pins[model] = transport.ModelPin{Repo: pin.Repo, Verifier: verifier}
	}
	seal, err := transport.NewGateway(transport.GatewayConfig{
		BaseURL:          baseURL,
		Relay:            base.Host,
		Catalog:          catalog,
		ModelPins:        pins,
		PinnedModelsOnly: opts.PinnedModelsOnly,
		Verifier:         defaults,
		UserCacheSecret:  cfg.userCacheSecret,
	})
	if err != nil {
		return nil, err
	}
	httpClient, err := transport.BoundHTTPClient(&http.Client{Transport: seal}, "", baseURL, "")
	if err != nil {
		return nil, err
	}
	openaiClient := openai.NewClient(append(cfg.openaiOpts, option.WithHTTPClient(httpClient), option.WithBaseURL(baseURL))...)
	return &Gateway{Client: &openaiClient, httpClient: httpClient, seal: seal}, nil
}

// HTTPClient seals requests to a replica of the model named in their body.
func (g *Gateway) HTTPClient() *http.Client {
	return g.httpClient
}

// GatewayVerification holds a replica's last successful verification.
//
// Deprecated: use ReplicaVerification.
type GatewayVerification = transport.ReplicaVerification

// ReplicaVerification holds a gateway replica's last successful verification.
type ReplicaVerification = transport.ReplicaVerification

// Verifications returns cached results without re-verifying them.
// Results may be expired or invalidated.
func (g *Gateway) Verifications() []GatewayVerification {
	return g.seal.Verifications()
}

// Serves checks the current catalog against the gateway policy without verifying replicas.
//
// Deprecated: use GatewayClient.Models.
func (g *Gateway) Serves(model string) bool {
	return g.seal.Serves(model)
}

// GatewayClient is an *http.Client for Tinfoil inference through the gateway.
// Each request is sealed to a verified replica of the model it names.
type GatewayClient struct {
	*http.Client
	// secure is the client OpenAI views use, which changes to the embedded
	// client can't reach.
	secure  *http.Client
	baseURL string
	seal    *transport.Gateway
}

// NewGatewayClient copies opts, and fetches the gateway's catalog unless
// opts.Catalog supplies it. Replicas are verified on first use.
func NewGatewayClient(opts *GatewayOptions) (*GatewayClient, error) {
	if opts == nil {
		opts = &GatewayOptions{}
	}
	if len(opts.ClientOptions) > 0 {
		return nil, &ConfigurationError{Err: fmt.Errorf("ClientOptions require NewGateway; set Verifier and UserCacheSecret, and pass OpenAI options to OpenAI")}
	}
	baseURL := cmp.Or(opts.URL, defaultGatewayURL)
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway base URL must be an absolute HTTPS URL: %q", baseURL)}
	}
	pins := make(map[string]transport.ModelPin, len(opts.ModelPins))
	for model, pin := range opts.ModelPins {
		if pin.Verification != nil {
			return nil, &ConfigurationError{Err: fmt.Errorf("model %q: ModelPin.Verification requires NewGateway; set Verifier", model)}
		}
		pins[model] = transport.ModelPin{Repo: pin.Repo, Verifier: pin.Verifier}
	}
	seal, err := transport.NewGateway(transport.GatewayConfig{
		BaseURL:          baseURL,
		Relay:            base.Host,
		Catalog:          opts.Catalog,
		ModelPins:        pins,
		PinnedModelsOnly: opts.PinnedModelsOnly,
		Verifier:         opts.Verifier,
		UserCacheSecret:  opts.UserCacheSecret,
	})
	if err != nil {
		return nil, err
	}
	secure, err := transport.BoundHTTPClient(&http.Client{Transport: seal}, "", baseURL, "")
	if err != nil {
		return nil, err
	}
	return &GatewayClient{Client: &http.Client{Transport: secure.Transport}, secure: secure, baseURL: baseURL, seal: seal}, nil
}

// BaseURL returns the gateway's base URL, which requests are sent to.
func (c *GatewayClient) BaseURL() string {
	return c.baseURL
}

// Models returns the catalog's models that the client's policy serves,
// sorted, without verifying replicas.
func (c *GatewayClient) Models(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.seal.Models(), nil
}

// EnsureVerified returns a verification that is valid now of a replica
// serving model, verifying replicas only if needed.
func (c *GatewayClient) EnsureVerified(ctx context.Context, model string) (*verify.Verification, error) {
	return c.seal.EnsureVerified(ctx, model)
}

// Current returns the last successful verification of each replica used so
// far, without checking them. They may have expired or been rejected.
func (c *GatewayClient) Current() []ReplicaVerification {
	return c.seal.Verifications()
}

// OpenAI returns an OpenAI client that sends its requests through c.
func (c *GatewayClient) OpenAI(opts ...option.RequestOption) *openai.Client {
	client := openai.NewClient(append(slices.Clone(opts), option.WithHTTPClient(c.secure), option.WithBaseURL(c.baseURL))...)
	return &client
}
