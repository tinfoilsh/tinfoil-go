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
	enclave, repo, relay string
	options              VerificationOptions
	autoSelect           bool

	stateMu      sync.RWMutex
	enclaves     map[string]*enclaveEntry
	selecting    *selectionCall
	selection    uint64
	tlsTransport *refreshingTransport
	verify       func(string) (*VerifiedDocumentV3, error)
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

// NewDefaultClient applies opts to every discovered router and fallback.
func NewDefaultClient(opts *VerificationOptions) (*SecureClient, error) {
	s, err := NewSecureClient(fallbackEnclave, defaultRouterRepo, opts)
	if err != nil {
		return nil, err
	}
	s.autoSelect = true
	if _, err := s.selectRouter(context.Background(), nil); err != nil {
		return nil, err
	}
	return s, nil
}

// ForEnclave keeps the repository reference and verification options.
func (s *SecureClient) ForEnclave(enclave string) *SecureClient {
	return &SecureClient{enclave: enclave, repo: s.repo, options: s.options}
}

// ViaRelay fetches attestation through relay, which forwards it to the enclave.
func (s *SecureClient) ViaRelay(relay string) *SecureClient {
	return &SecureClient{enclave: s.Enclave(), repo: s.repo, relay: relay, options: s.options}
}

// Enclave returns the enclave URL
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
	entry := s.enclaves[s.enclave]
	if entry == nil || entry.state == nil {
		return nil
	}
	return cloneVerification(entry.state.VerifiedDocumentV3)
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
	if s == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("secure client is required")}
	}
	s.stateMu.Lock()
	if s.tlsTransport == nil {
		s.tlsTransport = &refreshingTransport{client: s, build: func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
			key, err := verified.TLSPublicKeyFP()
			if err != nil {
				return nil, err
			}
			return &TLSBoundRoundTripper{ExpectedPublicKey: key, enclave: verified.EnclaveHost}, nil
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

type selectionCall struct {
	done       chan struct{}
	generation uint64
	observed   *enclaveState
	state      *enclaveState
	err        error
}

func (s *SecureClient) ready(ctx context.Context, transport *refreshingTransport, rejected *enclaveState) (*enclaveState, error) {
	s.stateMu.Lock()
	enclave := s.enclave
	state := s.entry(enclave).state
	reselect := s.autoSelect && (state == nil || state.rejected) && (rejected == nil || state == rejected)
	s.stateMu.Unlock()
	if reselect {
		selected, err := s.selectRouter(ctx, transport)
		if err != nil {
			return nil, err
		}
		return s.prepareTransport(ctx, selected.EnclaveHost, transport, verificationRetries)
	}
	if rejected != nil {
		enclave = rejected.EnclaveHost
	}
	return s.prepareTransport(ctx, enclave, transport, verificationRetries)
}

func (s *SecureClient) selectRouter(ctx context.Context, transport *refreshingTransport) (*enclaveState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.stateMu.Lock()
	observed := s.entry(s.enclave).state
	call := s.selecting
	if call == nil || call.generation != s.selection || call.observed != observed {
		call = &selectionCall{done: make(chan struct{}), generation: s.selection, observed: observed}
		s.selecting = call
		go s.discoverRouter(call, transport)
	}
	s.stateMu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return call.state, call.err
}

func (s *SecureClient) discoverRouter(call *selectionCall, transport *refreshingTransport) {
	var state *enclaveState
	var err, firstErr error
	for attempt := 0; ; attempt++ {
		routers, discoveryErr := fetchRouters()
		var failures []error
		if discoveryErr != nil {
			failures = append(failures, &FetchError{Err: fmt.Errorf("discovering routers: %w", discoveryErr)})
		}
		for _, enclave := range append(routers, fallbackEnclave) {
			state, err = s.prepareTransport(context.Background(), enclave, transport, candidateVerificationRetries)
			if err == nil {
				break
			}
			failures = append(failures, fmt.Errorf("verifying router %q: %w", enclave, err))
		}
		if err != nil {
			err = errors.Join(err, errors.Join(failures...))
		}
		if attempt == verificationRetries || !retryableVerification(err) {
			break
		}
		firstErr = err
		time.Sleep(verificationRetryDelay)
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err == nil && !state.valid() {
		err = &AttestationError{Err: errFreshnessExpired}
	}
	if err != nil && firstErr != nil {
		err = errors.Join(err, firstErr)
	}
	if err == nil {
		if s.selection == call.generation && s.entry(s.enclave).state == call.observed {
			s.enclave = state.EnclaveHost
			s.selection++
		}
		call.state = state
	}
	call.err = err
	if s.selecting == call {
		s.selecting = nil
	}
	close(call.done)
}
