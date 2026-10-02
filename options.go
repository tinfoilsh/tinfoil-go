package tinfoil

import (
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/verify/client"
)

const (
	defaultTransportMode = TransportEHBP
	defaultConfigRepo    = "tinfoilsh/confidential-model-router"
)

type clientConfig struct {
	enclave            string
	repo               string
	verification       client.VerificationOptions
	transport          TransportMode
	baseURL            string
	baseURLSet         bool
	userCacheSecret    string
	userCacheSecretSet bool
	openaiOpts         []option.RequestOption
}

// ClientOption configures a Client created with NewClientWithOptions.
type ClientOption func(*clientConfig)

// WithEnclave sets the enclave host to verify and connect to. When unset, a
// router is selected automatically.
func WithEnclave(enclave string) ClientOption {
	return func(c *clientConfig) { c.enclave = enclave }
}

// WithRepo sets the trusted repository reference, owner/name[@tag][@sha256:digest].
// A reference other than the default repository requires WithEnclave.
func WithRepo(repo string) ClientOption {
	return func(c *clientConfig) { c.repo = repo }
}

// WithVerificationOptions sets the policy applied to enclave verification.
// The client copies opts and its pins at construction, including for router discovery.
func WithVerificationOptions(opts client.VerificationOptions) ClientOption {
	return func(c *clientConfig) { c.verification = opts }
}

// WithTransport selects the transport mode. Defaults to TransportEHBP.
func WithTransport(mode TransportMode) ClientOption {
	return func(c *clientConfig) { c.transport = mode }
}

// WithBaseURL routes requests through the given HTTPS base URL (for example your own
// proxy) instead of sending them directly to the enclave. Request bodies stay
// encrypted end-to-end to the verified enclave; when the base URL's origin
// differs from the enclave's, the SDK adds the X-Tinfoil-Enclave-Url header so
// the proxy can forward the encrypted request to the right enclave. Only
// supported with the EHBP transport unless it uses the verified enclave's
// HTTPS origin.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *clientConfig) {
		c.baseURL = baseURL
		c.baseURLSet = true
	}
}

// WithOpenAIOptions appends options passed through to the underlying OpenAI client.
func WithOpenAIOptions(opts ...option.RequestOption) ClientOption {
	return func(c *clientConfig) { c.openaiOpts = append(c.openaiOpts, opts...) }
}

// WithUserCacheSecret sets the user cache secret explicitly, taking precedence
// over the environment variable and the generated secret. Use one stable value
// per end user: a server holding many end users' conversations should instead
// set a non-empty string field on every request, which wins over the
// client-level secret:
//
//	client.Chat.Completions.New(ctx, params,
//		option.WithJSONSet("user_cache_secret", perUserSecret))
//
// An empty string is treated as unset and falls through to the environment or
// generated secret.
func WithUserCacheSecret(secret string) ClientOption {
	return func(c *clientConfig) {
		c.userCacheSecret = secret
		c.userCacheSecretSet = secret != ""
	}
}
