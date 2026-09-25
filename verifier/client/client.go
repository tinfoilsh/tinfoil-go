package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

type SecureClient struct {
	enclave, repo, relay string
	// core is the immutable verification policy, shared by every client
	// derived from this one.
	core *verifier.Verifier

	stateMu    sync.RWMutex
	state      *VerifiedDocumentV3
	refreshing *verificationCall
	verify     func() (*VerifiedDocumentV3, error)
}

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
)

func fetchRouters() ([]string, error) {
	resp, _, err := util.Get(defaultRouterURL)
	if err != nil {
		return nil, err
	}

	var routers []string
	if err := json.Unmarshal(resp, &routers); err != nil {
		return nil, err
	}

	return routers, nil
}

// VerificationOptions is copied at construction. Create a new client to change it.
type VerificationOptions struct {
	// PinnedRegisters adds register checks; empty entries retain defaults.
	PinnedRegisters *measurement.Measurement `json:"pinned_registers,omitempty"`
	// FreshnessMaxAge defaults to seven days when zero. Negative ages are invalid.
	FreshnessMaxAge time.Duration `json:"freshness_max_age_ns,omitempty"`
}

// verifier builds the immutable policy these options describe, validating
// them once. A nil receiver selects the defaults.
func (input *VerificationOptions) verifier() (*verifier.Verifier, error) {
	if input == nil {
		return verifier.New()
	}
	return verifier.New(
		verifier.WithPinnedRegisters(input.PinnedRegisters),
		verifier.WithFreshnessMaxAge(input.FreshnessMaxAge),
	)
}

// NewSecureClient creates a secure client for an enclave and repository
// reference, owner/name[@tag][@sha256:digest]. Verification happens on first use.
func NewSecureClient(enclave, repo string, opts *VerificationOptions) (*SecureClient, error) {
	if _, _, _, err := provenance.ParseReference(repo); err != nil {
		return nil, &ConfigurationError{Err: err}
	}
	core, err := opts.verifier()
	if err != nil {
		return nil, err
	}
	return &SecureClient{enclave: enclave, repo: repo, core: core}, nil
}

// NewDefaultClient applies opts to every discovered router and fallback.
func NewDefaultClient(opts *VerificationOptions) (*SecureClient, error) {
	fallback, err := NewSecureClient("inference.tinfoil.sh", defaultRouterRepo, opts)
	if err != nil {
		return nil, err
	}
	routers, _ := fetchRouters()
	for _, routerURL := range routers {
		client := fallback.ForEnclave(routerURL)
		_, err := client.Verify()
		if err == nil {
			return client, nil
		}
	}

	return fallback, nil
}

// ForEnclave keeps the repository reference and verification options.
func (s *SecureClient) ForEnclave(enclave string) *SecureClient {
	return &SecureClient{enclave: enclave, repo: s.repo, core: s.core}
}

// ViaRelay fetches attestation through relay, which forwards it to the enclave.
func (s *SecureClient) ViaRelay(relay string) *SecureClient {
	return &SecureClient{enclave: s.enclave, repo: s.repo, relay: relay, core: s.core}
}

// Enclave returns the enclave URL
func (s *SecureClient) Enclave() string {
	return s.enclave
}

// Repo returns the trusted repository reference, including any tag or digest pins.
func (s *SecureClient) Repo() string {
	return s.repo
}

// Verification returns a copy of the last verified enclave state.
func (s *SecureClient) Verification() *VerifiedDocumentV3 {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return cloneVerification(s.state)
}

// VerificationJSON returns the last verification as JSON.
func (s *SecureClient) VerificationJSON() (string, error) {
	encoded, err := json.Marshal(s.Verification())
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave
func (s *SecureClient) HTTPClient() (*http.Client, error) {
	transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
		key, err := verified.TLSPublicKeyFP()
		if err != nil {
			return nil, err
		}
		return &TLSBoundRoundTripper{ExpectedPublicKey: key}, nil
	}, isCertificateError)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport}, nil
}

// Request sends an HTTPS request. headersJSON is a JSON object or empty.
func (s *SecureClient) Request(method, url, headersJSON string, body []byte) (result *Response, err error) {
	defer func() { err = mobileError(err) }()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, &ConfigurationError{Err: err}
	}
	if headersJSON != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			return nil, &ConfigurationError{Err: fmt.Errorf("failed to parse headers JSON: %w", err)}
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	httpClient, err := s.HTTPClient()
	if err != nil {
		return nil, err
	}

	if req.URL.Host == "" {
		req.URL.Scheme = "https"
		req.URL.Host = s.Enclave()
	}

	// Request headers (which may carry the API key) are not encrypted, so never
	// send them over a plaintext connection.
	if req.URL.Scheme != "https" {
		return nil, &ConfigurationError{Err: fmt.Errorf("refusing to send request over non-https URL %q", req.URL.String())}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponse(resp)
}
