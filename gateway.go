package tinfoil

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/client"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Gateway is an OpenAI client that seals each request to a verified replica
// of the model it names.
type Gateway struct {
	*openai.Client
	httpClient *http.Client
	seal       *sealTransport
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
type ModelPin struct {
	Repo         string
	Verification *client.VerificationOptions
}

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
	policy, err := newGatewayPolicy(opts, cfg.verification)
	if err != nil {
		return nil, &ConfigurationError{Err: err}
	}
	if catalog == nil {
		fetched, err := FetchCatalog(base.Host)
		if err != nil {
			return nil, err
		}
		catalog = func() Catalog { return fetched }
	}
	seal := &sealTransport{
		catalog: catalog,
		policy:  policy,
		secret:  resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet),
		build: func(r replica) (http.RoundTripper, error) {
			secure, pinned := policy.pins[r.model]
			var err error
			if pinned {
				secure = secure.ForEnclave(r.host)
			} else if secure, err = client.NewSecureClient(r.host, r.ref, &policy.defaults); err != nil {
				return nil, err
			}
			secure = secure.ViaRelay(base.Host)
			httpClient, err := ehbpHTTPClient(secure, r.host, baseURL)
			if err != nil {
				return nil, err
			}
			return &verifiedReplicaTransport{
				recoveryTransport: &recoveryTransport{transport: httpClient.Transport},
				verification:      secure.Verification,
			}, nil
		},
	}
	httpClient, err := boundHTTPClient(&http.Client{Transport: seal}, "", baseURL, "")
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
type GatewayVerification struct {
	// Host is the replica the verification is for.
	Host string `json:"host"`
	// Request model names, not attested identities.
	Models       []string             `json:"models"`
	Reference    string               `json:"reference"`
	PinnedModel  string               `json:"pinned_model,omitempty"`
	Verification *verify.Verification `json:"verification"`
}

// Verifications returns cached results without re-verifying them.
// Results may be expired or invalidated.
func (g *Gateway) Verifications() []GatewayVerification {
	results := []GatewayVerification{}
	g.seal.enclaves.Range(func(key, value any) bool {
		r := key.(replica)
		transport, ok := value.(*verifiedReplicaTransport)
		if !ok {
			return true
		}
		if verified := transport.verification(); verified != nil {
			models := []string{}
			transport.models.Range(func(model, _ any) bool {
				models = append(models, model.(string))
				return true
			})
			slices.Sort(models)
			results = append(results, GatewayVerification{Host: r.host, Models: models, Reference: r.ref, PinnedModel: r.model, Verification: verified})
		}
		return true
	})
	slices.SortFunc(results, func(a, b GatewayVerification) int {
		return cmp.Or(strings.Compare(a.Host, b.Host),
			strings.Compare(a.Reference, b.Reference), strings.Compare(a.PinnedModel, b.PinnedModel))
	})
	return results
}

type verifiedReplicaTransport struct {
	*recoveryTransport
	verification func() *verify.Verification
	models       sync.Map
}

func (t *verifiedReplicaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.models.Store(req.Header.Get(modelHeader), struct{}{})
	return t.recoveryTransport.RoundTrip(req)
}

// Serves checks the current catalog against the gateway policy without verifying replicas.
func (g *Gateway) Serves(model string) bool {
	_, _, err := g.seal.policy.resolve(model, g.seal.catalog())
	return err == nil
}
