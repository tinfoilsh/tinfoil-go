package client

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

type SecureClient struct {
	repo       string
	options    VerificationOptions
	autoSelect bool

	stateMu    sync.RWMutex
	enclave    string // Selected endpoint, protected by stateMu.
	state      *VerifiedDocumentV3
	refreshing *verificationCall
	verify     func(string) (*VerifiedDocumentV3, error)
}

const (
	fallbackEnclave         = "inference.tinfoil.sh"
	routerDiscoveryTimeout  = 30 * time.Second
	maxRouterDiscoveryBytes = 32 << 20
)

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
)

func fetchRouters() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routerDiscoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, defaultRouterURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP GET %s: %d %s", defaultRouterURL, resp.StatusCode, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRouterDiscoveryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRouterDiscoveryBytes {
		return nil, fmt.Errorf("router discovery response exceeds %d bytes", maxRouterDiscoveryBytes)
	}

	var routers []string
	if err := json.Unmarshal(body, &routers); err != nil {
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

func (input *VerificationOptions) normalized() (VerificationOptions, error) {
	var opts VerificationOptions
	if input != nil {
		opts = *input
	}
	if opts.FreshnessMaxAge < 0 {
		return VerificationOptions{}, &ConfigurationError{Err: fmt.Errorf("freshness maximum age must not be negative")}
	}
	opts.FreshnessMaxAge = cmp.Or(opts.FreshnessMaxAge, provenance.MaxFreshnessAge)
	opts.PinnedRegisters = cloneMeasurement(opts.PinnedRegisters)
	if err := measurement.ValidatePins(opts.PinnedRegisters); err != nil {
		return VerificationOptions{}, &ConfigurationError{Err: err}
	}
	return opts, nil
}

// NewSecureClient creates a secure client for an enclave and repository
// reference, owner/name[@tag][@sha256:digest]. Verification happens on first use.
func NewSecureClient(enclave, repo string, opts *VerificationOptions) (*SecureClient, error) {
	if _, _, _, err := provenance.ParseReference(repo); err != nil {
		return nil, &ConfigurationError{Err: err}
	}
	options, err := opts.normalized()
	if err != nil {
		return nil, err
	}
	return &SecureClient{enclave: enclave, repo: repo, options: options}, nil
}

// NewDefaultClient selects and verifies a router, applying opts to every
// candidate and fallback. Only client initialization and key recovery select routers.
func NewDefaultClient(opts *VerificationOptions) (*SecureClient, error) {
	s, err := NewSecureClient(fallbackEnclave, defaultRouterRepo, opts)
	if err != nil {
		return nil, err
	}
	s.autoSelect = true
	if _, err := s.ready(context.Background(), nil); err != nil {
		return nil, err
	}
	return s, nil
}

// ready coordinates client setup and recovery. Ordinary verification and
// freshness refresh stay on the selected enclave; key recovery may reselect it.
func (s *SecureClient) ready(ctx context.Context, rejected *VerifiedDocumentV3) (*VerifiedDocumentV3, error) {
	return s.refreshState(ctx, rejected, rejected != nil, func() (*VerifiedDocumentV3, error) {
		s.stateMu.RLock()
		initializing := s.state == nil
		enclave := s.enclave
		s.stateMu.RUnlock()
		if s.autoSelect && (initializing || rejected != nil) {
			return s.selectRouter()
		}
		return s.fetchEnclaveVerification(enclave)
	})
}

func (s *SecureClient) selectRouter() (*VerifiedDocumentV3, error) {
	routers, err := fetchRouters()
	var failures []error
	if err != nil {
		failures = append(failures, &FetchError{Err: fmt.Errorf("discovering routers: %w", err)})
	}
	for _, routerURL := range routers {
		// One probe per candidate; the shared recovery loop owns the retry budget.
		state, err := s.fetchEnclaveVerification(routerURL)
		if err == nil {
			return state, nil
		}
		failures = append(failures, fmt.Errorf("verifying router %q: %w", routerURL, err))
	}

	state, err := s.fetchEnclaveVerification(fallbackEnclave)
	if err != nil {
		return nil, errors.Join(err, errors.Join(failures...))
	}
	return state, nil
}

// ForEnclave keeps the repository reference and verification options.
func (s *SecureClient) ForEnclave(enclave string) *SecureClient {
	return &SecureClient{enclave: enclave, repo: s.repo, options: s.options}
}

// Enclave returns the selected enclave host. A default client may select another
// router during key recovery; verification alone does not change the endpoint.
func (s *SecureClient) Enclave() string {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
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

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave.
// Default clients route HTTPS requests to the currently verified router.
func (s *SecureClient) HTTPClient() (*http.Client, error) {
	transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
		key, err := verified.TLSPublicKeyFP()
		if err != nil {
			return nil, err
		}
		transport := &TLSBoundRoundTripper{ExpectedPublicKey: key}
		if s.autoSelect {
			transport.enclave = verified.EnclaveHost
		}
		return transport, nil
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
