package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier"
	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

type SecureClient struct {
	enclave, repo, relay string
	// core is the immutable verification policy, shared by every client
	// derived from this one.
	core *verifier.Verifier

	stateMu      sync.RWMutex
	state        *enclaveState
	refreshing   *verificationCall
	tlsTransport *clientTransport
	verify       func() (*VerifiedDocumentV3, error)
}

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
)

const (
	routerFetchTimeout    = 30 * time.Second
	maxRouterResponseSize = 32 << 20
)

func fetchRouters() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routerFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultRouterURL, nil)
	if err != nil {
		return nil, &FetchError{Err: err}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &FetchError{Err: err}
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &FetchError{Err: fmt.Errorf("router discovery: %s", resp.Status)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRouterResponseSize+1))
	if err != nil {
		return nil, &FetchError{Err: err}
	}
	if len(body) > maxRouterResponseSize {
		return nil, &FetchError{Err: fmt.Errorf("router discovery response exceeds %d bytes", maxRouterResponseSize)}
	}
	var routers []string
	if err := json.Unmarshal(body, &routers); err != nil {
		return nil, &FetchError{Err: err}
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

// NewDefaultClient selects a fixed-enclave client, applying opts to every candidate.
// The returned client does not rediscover routers or change its endpoint.
func NewDefaultClient(opts *VerificationOptions) (*SecureClient, error) {
	fallback, err := NewSecureClient("inference.tinfoil.sh", defaultRouterRepo, opts)
	if err != nil {
		return nil, err
	}
	routers, _ := fetchRouters()
	for _, routerURL := range routers {
		client := fallback.ForEnclave(routerURL)
		_, err := client.verifiedState(context.Background(), true, candidateVerificationRetries)
		if err == nil {
			return client, nil
		}
		if !retryableVerification(err) {
			return nil, err
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
	if s.state == nil {
		return nil
	}
	return cloneVerification(s.state.VerifiedDocumentV3)
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
	s.stateMu.Lock()
	if s.tlsTransport == nil {
		s.tlsTransport = &clientTransport{client: s, build: func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
			key, err := verified.TLSPublicKeyFP()
			if err != nil {
				return nil, err
			}
			return &TLSBoundRoundTripper{ExpectedPublicKey: key}, nil
		}, isKeyError: isCertificateError}
	}
	transport := s.tlsTransport
	s.stateMu.Unlock()
	if err := s.registerTransport(transport); err != nil {
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
