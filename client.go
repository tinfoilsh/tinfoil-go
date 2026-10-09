package tinfoil

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Client wraps the OpenAI client to provide secure inference through Tinfoil
type Client struct {
	*openai.Client
	secure     *enclave.Handle
	httpClient *http.Client
	transport  TransportMode
}

// NewClient creates a new secure OpenAI client using default parameters
func NewClient(openaiOpts ...option.RequestOption) (*Client, error) {
	handle, err := enclave.NewDefaultHandle(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create enclave handle: %w", err)
	}
	return createClientFromHandle(handle, defaultTransportMode, "", resolveUserCacheSecret("", false), openaiOpts...)
}

// NewClientWithOptions creates a secure OpenAI client configured through
// functional options. By default it selects a router automatically, verifies
// against the default config repository, and uses the EHBP transport.
func NewClientWithOptions(opts ...ClientOption) (*Client, error) {
	cfg := &clientConfig{
		transport: defaultTransportMode,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.transport == "" {
		cfg.transport = defaultTransportMode
	}
	if cfg.repo == "" && cfg.verification.EmbeddedConfig == nil {
		cfg.repo = defaultConfigRepo
	}
	if cfg.enclave == "" && cfg.verification.EmbeddedConfig != nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("embedded config requires an enclave")}
	}
	if cfg.transport != TransportTLS && cfg.transport != TransportEHBP {
		return nil, &ConfigurationError{Err: fmt.Errorf("unknown transport mode: %q", cfg.transport)}
	}
	if cfg.baseURLSet {
		origin, err := originOf(cfg.baseURL)
		if err != nil {
			return nil, &ConfigurationError{Err: fmt.Errorf("invalid base URL: %w", err)}
		}
		if !strings.HasPrefix(origin, "https://") {
			return nil, &ConfigurationError{Err: fmt.Errorf("invalid base URL: HTTPS is required to protect request headers")}
		}
	}
	if cfg.enclave == "" && cfg.repo != defaultConfigRepo {
		return nil, &ConfigurationError{Err: fmt.Errorf("custom repository requires an enclave")}
	}

	var handle *enclave.Handle
	var err error
	if cfg.enclave == "" {
		handle, err = enclave.NewDefaultHandle(&cfg.verification)
	} else {
		handle, err = enclave.NewHandle(cfg.enclave, cfg.repo, &cfg.verification)
	}
	if err != nil {
		return nil, err
	}

	return createClientFromHandle(handle, cfg.transport, cfg.baseURL,
		resolveUserCacheSecret(cfg.userCacheSecret, cfg.userCacheSecretSet), cfg.openaiOpts...)
}

func createClientFromHandle(handle *enclave.Handle, mode TransportMode, baseURL, userCacheSecret string, openaiOpts ...option.RequestOption) (*Client, error) {
	httpClient, err := secureHTTPClient(handle, mode, baseURL, userCacheSecret)
	if err != nil {
		return nil, err
	}

	resolvedBaseURL := baseURL
	if resolvedBaseURL == "" {
		resolvedBaseURL = fmt.Sprintf("https://%s/v1/", handle.Enclave())
	}

	// Add our HTTP client and base URL to the options
	allOpts := append(openaiOpts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(resolvedBaseURL),
	)

	openaiClient := openai.NewClient(allOpts...)
	return &Client{
		Client:     &openaiClient,
		secure:     handle,
		httpClient: httpClient,
		transport:  mode,
	}, nil
}

func (c *Client) Enclave() string {
	return c.secure.Enclave()
}

func (c *Client) Repo() string {
	return c.secure.Repo()
}

// Transport returns the transport mode used to secure traffic to the enclave.
func (c *Client) Transport() TransportMode {
	return c.transport
}

// Verify refreshes attestation and returns the verified state.
func (c *Client) Verify() (*verify.Verification, error) {
	return c.secure.Verify()
}

// Verification returns a copy of the last successful verification.
func (c *Client) Verification() *verify.Verification {
	return c.secure.Verification()
}

// HTTPClient returns the underlying HTTP client used to reach the enclave. It
// re-verifies before new requests when witnesses expire or the enclave rotates its key.
// It is bound to the verified enclave (and the configured proxy, if any):
// requests to any other origin are refused to avoid disclosing sensitive
// headers. This can be used for secure, direct HTTP requests to the enclave.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}
