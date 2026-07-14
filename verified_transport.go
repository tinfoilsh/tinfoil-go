package tinfoil

import (
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// VerifiedTransport is an attested sealing transport to a verified enclave:
// pinned TLS or EHBP, re-verifying attestation automatically when the enclave
// rotates its keys. Unlike the client returned by NewClientWithOptions it
// carries no OpenAI client or cache-secret layer. It is bound to the verified
// enclave and, when configured, the base URL's origin.
type VerifiedTransport struct {
	enclave   string
	repo      string
	transport http.RoundTripper
}

// NewVerifiedTransport verifies an enclave and returns its sealing transport.
// By default it selects a router automatically, verifies against the default
// config repository, and uses the EHBP transport. It honors WithEnclave,
// WithRepo, WithTransport, WithBaseURL, and WithAttestationBundleURL; options
// that only configure the OpenAI client or the cache-secret layer have no
// effect here.
func NewVerifiedTransport(opts ...ClientOption) (*VerifiedTransport, error) {
	cfg, err := newClientConfig(opts)
	if err != nil {
		return nil, err
	}
	secureClient, err := newSecureClientFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return newVerifiedTransport(secureClient, cfg.transport, cfg.baseURL)
}

func newVerifiedTransport(secureClient *client.SecureClient, mode TransportMode, baseURL string) (*VerifiedTransport, error) {
	httpClient, err := sealingHTTPClient(secureClient, mode, baseURL)
	if err != nil {
		return nil, err
	}
	transport, err := newHostBoundTransport(secureClient.Enclave(), baseURL, httpClient.Transport)
	if err != nil {
		return nil, err
	}
	return &VerifiedTransport{
		enclave:   secureClient.Enclave(),
		repo:      secureClient.Repo(),
		transport: transport,
	}, nil
}

// Enclave returns the verified enclave host requests are sealed to.
func (t *VerifiedTransport) Enclave() string {
	return t.enclave
}

// Repo returns the config repository the enclave was verified against.
func (t *VerifiedTransport) Repo() string {
	return t.repo
}

// RoundTrip sends the request over the sealed connection to the verified
// enclave.
func (t *VerifiedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.transport.RoundTrip(req)
}
