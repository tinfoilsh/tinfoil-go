package tinfoil

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/tinfoil-go/internal/gateway"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const defaultGatewayURL = "https://inference-gateway.tinfoil.sh/v1/"

// GatewayOptions configures a GatewayHTTPClient.
type GatewayOptions struct {
	// ModelPins pins models to repositories. With PinnedModelsOnly, only pinned
	// models are served, which requires at least one pin.
	ModelPins        map[string]ModelPin
	PinnedModelsOnly bool
	// Verifier is the policy for unpinned models; nil selects the defaults.
	Verifier *verify.Verifier
	// UserCacheSecret is the default prompt-cache scope for the client's
	// requests; empty resolves it from TINFOIL_USER_CACHE_SECRET or
	// ~/.tinfoil/user_cache_secret. A non-empty user_cache_secret string in a
	// request's JSON body overrides it, so a server can scope the cache to each
	// end user, for example with option.WithJSONSet("user_cache_secret", s).
	UserCacheSecret string
	// URL is the gateway's base URL; empty selects Tinfoil's gateway.
	URL string
	// Catalog is read on every request and must return an immutable map safe
	// for concurrent readers. nil fetches the gateway's catalog on first use
	// and refreshes it every 10 seconds while the client is used; a failed
	// refresh keeps the last catalog fetched.
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
type ReplicaVerification = gateway.ReplicaVerification

// GatewayHTTPClient is an *http.Client for Tinfoil inference through the gateway.
// Each request is sealed to a verified replica of the model it names, as with
// BindingEHBP: the gateway sees the method, URL and headers, and WebSocket
// upgrades are refused.
type GatewayHTTPClient struct {
	*http.Client
	// secure is the client OpenAI clients use, which changes to the embedded
	// client can't reach.
	secure  *http.Client
	baseURL string
	seal    *gateway.Transport
}

// NewGatewayHTTPClient copies opts and does no network I/O: the catalog is
// fetched and replicas are verified on first use.
func NewGatewayHTTPClient(opts *GatewayOptions) (*GatewayHTTPClient, error) {
	if opts == nil {
		opts = &GatewayOptions{}
	}
	baseURL := cmp.Or(opts.URL, defaultGatewayURL)
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway base URL must be an absolute HTTPS URL: %q", baseURL)}
	}
	pins := make(map[string]gateway.ModelPin, len(opts.ModelPins))
	for model, pin := range opts.ModelPins {
		pins[model] = gateway.ModelPin{Repo: pin.Repo, Verifier: pin.Verifier}
	}
	seal, err := gateway.NewTransport(gateway.Config{
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
	return &GatewayHTTPClient{Client: &http.Client{Transport: secure.Transport}, secure: secure, baseURL: baseURL, seal: seal}, nil
}

// BaseURL returns the gateway's base URL, which requests are sent to.
func (c *GatewayHTTPClient) BaseURL() string {
	return c.baseURL
}

// Models returns the catalog's models that the client's policy serves,
// sorted, without verifying replicas. A failed catalog refresh doesn't fail
// it; only the first fetch can.
func (c *GatewayHTTPClient) Models(ctx context.Context) ([]string, error) {
	return c.seal.Models(ctx)
}

// EnsureVerified returns a verification that is valid now of a replica
// serving model, verifying replicas only if needed.
func (c *GatewayHTTPClient) EnsureVerified(ctx context.Context, model string) (*verify.Verification, error) {
	return c.seal.EnsureVerified(ctx, model)
}

// Current returns the last successful verification of each replica used so
// far, without checking them. They may have expired or been rejected.
func (c *GatewayHTTPClient) Current() []ReplicaVerification {
	return c.seal.Verifications()
}
