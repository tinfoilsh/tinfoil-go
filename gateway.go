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
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const defaultGatewayURL = "https://inference-gateway.tinfoil.sh/v1/"

// GatewayOptions configures a GatewayClient.
type GatewayOptions struct {
	// ModelPins pins models to repositories. With PinnedModelsOnly, only pinned
	// models are served, which requires at least one pin.
	ModelPins        map[string]ModelPin
	PinnedModelsOnly bool
	// Verifier is the policy for unpinned models; nil selects the defaults.
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
	// Verifier is the pin's policy: nil inherits GatewayOptions.Verifier;
	// non-nil replaces it.
	Verifier *verify.Verifier
}

// ReplicaVerification holds a gateway replica's last successful verification.
type ReplicaVerification = transport.ReplicaVerification

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
	baseURL := cmp.Or(opts.URL, defaultGatewayURL)
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway base URL must be an absolute HTTPS URL: %q", baseURL)}
	}
	pins := make(map[string]transport.ModelPin, len(opts.ModelPins))
	for model, pin := range opts.ModelPins {
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
