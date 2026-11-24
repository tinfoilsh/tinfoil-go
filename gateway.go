package tinfoil

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/gateway"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const defaultGatewayURL = "https://inference-gateway.tinfoil.sh/"

// GatewayOptions configures a GatewayHTTPClient.
type GatewayOptions struct {
	// ModelPins pins models to repositories. The client serves only the
	// models that it has pins for, so at least one pin is required, and a
	// request for any other model fails with ErrConfiguration without
	// contacting a replica.
	ModelPins map[string]ModelPin
	// Policy is the verification policy for pins that set no Policy; the
	// zero Policy keeps every default.
	// The client copies it, so later changes by the caller have no effect.
	Policy verify.Policy
	// VerificationCheck is called with each replica's verified facts, as
	// EnclaveOptions.VerificationCheck is.
	// A replica that it rejects is skipped for the next replica of the model.
	VerificationCheck func(v *verify.VerifiedFacts) error
	// OnVerification, when set, is called once for every attempt to verify a
	// replica, with the replica's host, as EnclaveOptions.OnVerification
	// describes.
	OnVerification func(host string, report *verify.VerificationReport, err error)
	// UserCacheSecret is the default prompt-cache scope for the client's
	// requests. A non-empty user_cache_secret string in a request's JSON body
	// overrides it, so a server can scope the cache to each end user, for
	// example with option.WithJSONSet("user_cache_secret", s). When it is
	// empty, the client uses a random secret that is generated in memory once
	// per process and that every client in the process shares; no environment
	// variable or file is read. Applications that want a stable secret across
	// processes or machines pass it here.
	// Use an opaque random value, not a raw user ID or API key: the gateway
	// sees a cache prefix keyed on it, and could test guesses of a guessable
	// secret and then of the prompt.
	UserCacheSecret string
	// URL is the gateway's URL: its origin, or the URL that it is mounted
	// under; empty selects Tinfoil's gateway, https://inference-gateway.tinfoil.sh/.
	// Its path, if any, is where the gateway is mounted, not the API path,
	// as for an EHBP ProxyURL: the catalog, the attestation relay and an
	// OpenAIClient's API path, "/v1/" by default, all join under it, whether
	// or not it ends with a slash, so that https://gateway.example/tinfoil
	// sends chat completions to
	// https://gateway.example/tinfoil/v1/chat/completions. It must use HTTPS.
	// Request paths join under it, so a URL with user information, a query or
	// a fragment, even an empty one, is an ErrConfiguration error.
	URL string
	// Catalog is read on every request and must return an immutable map safe
	// for concurrent readers. nil fetches the gateway's catalog when the client
	// is created and refreshes it every 10 seconds while the client is used; a
	// failed refresh keeps the last catalog fetched.
	Catalog func() Catalog
}

// ModelPin pins a model to tinfoilsh/name[@tag][@sha256:digest].
type ModelPin struct {
	Repo string
	// Policy is the pin's verification policy: nil inherits
	// GatewayOptions.Policy, and non-nil replaces it entirely, so a field that
	// it leaves unset takes the default rather than the gateway's value.
	Policy *verify.Policy
}

// ReplicaVerification holds a gateway replica's last attempt at
// verification: its report if the attempt passed, and otherwise its error.
type ReplicaVerification = gateway.ReplicaVerification

// GatewayHTTPClient is an *http.Client for Tinfoil inference through the gateway.
// Each request is sealed to a verified replica of the model it names, as with
// the EHBP transport: the gateway sees the method, URL and headers, and
// WebSocket upgrades are refused. A JSON object body that repeats its model,
// user_cache_secret or cache_salt member is refused with ErrConfiguration
// before it is sent, since a server could read a different repeat from the one
// that the client routed on.
type GatewayHTTPClient struct {
	*http.Client
	// secure is the client OpenAI clients use, which changes to the embedded
	// client can't reach.
	secure    *http.Client
	baseURL   string
	transport *gateway.Transport
}

// NewGatewayHTTPClient copies opts and checks them before any network I/O,
// then fetches the catalog under ctx before it returns, so an unreachable
// gateway fails here rather than on its first request. A model's replicas are
// verified on its first request, so ModelPins may name models the catalog
// doesn't list.
//
// Experimental: the gateway route is new, and this API may change or be
// removed in a later release.
func NewGatewayHTTPClient(ctx context.Context, opts *GatewayOptions) (*GatewayHTTPClient, error) {
	c, err := unverifiedGatewayHTTPClient(opts)
	if err != nil {
		return nil, err
	}
	if _, err := c.transport.Models(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// unverifiedGatewayHTTPClient is NewGatewayHTTPClient without the network
// I/O: the catalog is fetched and replicas are verified on first use.
func unverifiedGatewayHTTPClient(opts *GatewayOptions) (*GatewayHTTPClient, error) {
	if opts == nil {
		opts = &GatewayOptions{}
	}
	baseURL := cmp.Or(opts.URL, defaultGatewayURL)
	if err := validateGatewayURL(baseURL); err != nil {
		return nil, err
	}
	pins := make(map[string]gateway.ModelPin, len(opts.ModelPins))
	for model, pin := range opts.ModelPins {
		pins[model] = gateway.ModelPin{Repo: pin.Repo, Policy: pin.Policy}
	}
	gatewayTransport, err := gateway.NewTransport(gateway.Config{
		BaseURL:           baseURL,
		Catalog:           opts.Catalog,
		ModelPins:         pins,
		Policy:            opts.Policy,
		VerificationCheck: opts.VerificationCheck,
		OnVerification:    opts.OnVerification,
		UserCacheSecret:   opts.UserCacheSecret,
	})
	if err != nil {
		return nil, err
	}
	guarded, err := transport.WithOriginRestriction(gatewayTransport, "", baseURL)
	if err != nil {
		return nil, err
	}
	secure := &http.Client{Transport: guarded}
	return &GatewayHTTPClient{Client: &http.Client{Transport: secure.Transport}, secure: secure, baseURL: baseURL, transport: gatewayTransport}, nil
}

// validateGatewayURL requires an absolute HTTPS URL without user
// information, a query or a fragment.
func validateGatewayURL(baseURL string) error {
	if _, err := transport.OriginOf(baseURL); err != nil {
		return errs.Configuration(fmt.Errorf("invalid base URL: %w", err))
	}
	if err := refuseQueryOrFragment("base URL", baseURL); err != nil {
		return err
	}
	base, _ := url.Parse(baseURL) // OriginOf parsed it
	if base.Scheme != "https" {
		return errs.Configuration(fmt.Errorf("invalid base URL: the gateway base URL must use HTTPS: %q", baseURL))
	}
	return nil
}

// BaseURL returns the gateway's URL, GatewayOptions.URL or Tinfoil's gateway
// by default, which requests are sent to and which an OpenAIClient joins its
// API path under, as EnclaveHTTPClient.BaseURL returns an EHBP ProxyURL.
func (c *GatewayHTTPClient) BaseURL() string {
	return c.baseURL
}

// Models returns the catalog's models that the client's policy serves,
// sorted, without verifying replicas. A failed catalog refresh doesn't fail
// it; only the first fetch can.
func (c *GatewayHTTPClient) Models(ctx context.Context) ([]string, error) {
	return c.transport.Models(ctx)
}

// EnsureVerified returns the report of a verification that is valid now of
// a replica serving model, verifying replicas only if needed. The report is a
// copy for the caller to keep.
func (c *GatewayHTTPClient) EnsureVerified(ctx context.Context, model string) (*verify.VerificationReport, error) {
	return c.transport.EnsureVerified(ctx, model)
}

// LastVerification returns one entry for each replica that the client has
// tried to verify, failed replicas included, each holding that replica's
// last attempt, without I/O: its report if the attempt passed, and otherwise
// its error, as RouterHTTPClient.LastVerification describes. A replica's
// earlier success is not kept once a later attempt for it fails. Reports
// may have expired or been rejected since.
func (c *GatewayHTTPClient) LastVerification() []ReplicaVerification {
	return c.transport.LastVerification()
}
