package tinfoil

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
)

// Gateway is an OpenAI client that seals each request to a verified replica
// of the model it names.
type Gateway struct {
	*openai.Client
	httpClient *http.Client
	seal       *transport.Gateway
}

type GatewayOptions struct {
	// Routing overrides and non-EHBP transports are rejected.
	ClientOptions []ClientOption
	ModelPins     map[string]ModelPin
	// Requires at least one pin.
	PinnedModelsOnly bool
}

// ModelPin pins a model to tinfoilsh/name[@tag][@sha256:digest].
// Nil Verification inherits gateway defaults; non-nil replaces them.
// Zero FreshnessMaxAge in a replacement uses the SDK's seven-day default.
type ModelPin = transport.ModelPin

// NewGateway copies opts and reads catalog on every request; nil fetches it once.
// Catalog callbacks must return immutable maps safe for concurrent readers.
// Replicas are verified on first use.
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
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, &ConfigurationError{Err: fmt.Errorf("gateway base URL must be an absolute HTTPS URL: %q", baseURL)}
	}
	seal, err := transport.NewGateway(transport.GatewayConfig{
		BaseURL:          baseURL,
		Relay:            base.Host,
		Catalog:          catalog,
		ModelPins:        opts.ModelPins,
		PinnedModelsOnly: opts.PinnedModelsOnly,
		Defaults:         cfg.verification,
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
type GatewayVerification = transport.ReplicaVerification

// Verifications returns cached results without re-verifying them.
// Results may be expired or invalidated.
func (g *Gateway) Verifications() []GatewayVerification {
	return g.seal.Verifications()
}

// Serves checks the current catalog against the gateway policy without verifying replicas.
func (g *Gateway) Serves(model string) bool {
	return g.seal.Serves(model)
}
