package client

import (
	"bytes"
	"cmp"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

// GroundTruth records verified measurements and transport keys.
type GroundTruth struct {
	ConfigRepo         string                   `json:"config_repo,omitempty"`
	EnclaveHost        string                   `json:"enclave_host,omitempty"`
	ReleaseTag         string                   `json:"release_tag,omitempty"`
	TLSPublicKey       string                   `json:"tls_public_key,omitempty"`
	HPKEPublicKey      string                   `json:"hpke_public_key,omitempty"`
	Digest             string                   `json:"digest"`
	CodeMeasurement    *measurement.Measurement `json:"code_measurement"`
	EnclaveMeasurement *measurement.Measurement `json:"enclave_measurement"`
	CodeFingerprint    string                   `json:"code_fingerprint"`
	EnclaveFingerprint string                   `json:"enclave_fingerprint"`
	Verifier           SoftwareIdentity         `json:"verifier"`
	VerifiedAt         string                   `json:"verified_at"`
}

type SecureClient struct {
	enclave, repo string
	options       VerificationOptions

	stateMu    sync.RWMutex
	state      *verificationState
	refreshing *verificationCall
	verify     func() (*verificationState, error)
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

// NewSecureClient uses the default verification options.
func NewSecureClient(enclave, repo string) *SecureClient {
	client, _ := NewSecureClientWithOptions(enclave, repo, VerificationOptions{})
	return client
}

// VerificationOptions is copied at construction. Create a new client to change it.
type VerificationOptions struct {
	// PinnedRegisters adds register checks; empty entries retain defaults.
	PinnedRegisters *measurement.Measurement `json:"pinned_registers,omitempty"`
	// FreshnessMaxAge defaults to seven days when zero. Negative ages are invalid.
	FreshnessMaxAge time.Duration `json:"freshness_max_age_ns,omitempty"`
}

func (opts VerificationOptions) normalized() (VerificationOptions, error) {
	if opts.FreshnessMaxAge < 0 {
		return VerificationOptions{}, fmt.Errorf("freshness maximum age must not be negative")
	}
	opts.FreshnessMaxAge = cmp.Or(opts.FreshnessMaxAge, provenance.MaxFreshnessAge)
	opts.PinnedRegisters = cloneMeasurement(opts.PinnedRegisters)
	return opts, nil
}

// NewSecureClientWithOptions creates a secure client for an enclave and repository
// reference, owner/name[@tag][@sha256:digest]. Verification happens on first use.
func NewSecureClientWithOptions(enclave, repo string, opts VerificationOptions) (*SecureClient, error) {
	opts, err := opts.normalized()
	if err != nil {
		return nil, err
	}
	return &SecureClient{enclave: enclave, repo: repo, options: opts}, nil
}

// NewDefaultClient returns the first router that verifies, or a client for
// inference.tinfoil.sh if discovery or verification fails.
func NewDefaultClient() (*SecureClient, error) {
	return NewDefaultClientWithOptions(VerificationOptions{})
}

// NewDefaultClientWithOptions applies opts to every discovered router and fallback.
func NewDefaultClientWithOptions(opts VerificationOptions) (*SecureClient, error) {
	fallback, err := NewSecureClientWithOptions("inference.tinfoil.sh", defaultRouterRepo, opts)
	if err != nil {
		return nil, err
	}
	routers, _ := fetchRouters()
	for _, routerURL := range routers {
		// Reuse the immutable policy snapshot copied before discovery.
		client := &SecureClient{enclave: routerURL, repo: defaultRouterRepo, options: fallback.options}
		_, err := client.Verify()
		if err == nil {
			return client, nil
		}
	}

	return fallback, nil
}

// Enclave returns the enclave host.
func (s *SecureClient) Enclave() string {
	return s.enclave
}

// Repo returns the trusted repository reference, including any tag or digest pins.
func (s *SecureClient) Repo() string {
	return s.repo
}

// GroundTruth returns the last verified enclave state
func (s *SecureClient) GroundTruth() *GroundTruth {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if s.state == nil {
		return nil
	}
	return cloneGroundTruth(s.state.groundTruth)
}

// GroundTruthJSON returns the ground truth as a JSON string
func (s *SecureClient) GroundTruthJSON() (string, error) {
	encoded, err := json.Marshal(s.GroundTruth())
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// VerificationDocument returns the result of the last successful verification.
func (s *SecureClient) VerificationDocument() *VerificationDocument {
	return newVerificationDocument(s.GroundTruth())
}

// VerificationDocumentJSON returns the verification document as JSON.
func (s *SecureClient) VerificationDocumentJSON() (string, error) {
	encoded, err := json.Marshal(s.VerificationDocument())
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave
func (s *SecureClient) HTTPClient() (*http.Client, error) {
	transport, err := s.NewTransport(func(groundTruth *GroundTruth) (http.RoundTripper, error) {
		return &TLSBoundRoundTripper{ExpectedPublicKey: groundTruth.TLSPublicKey}, nil
	}, isCertificateError)
	if err != nil {
		return nil, fmt.Errorf("creating TLS transport: %w", err)
	}
	return &http.Client{Transport: transport}, nil
}

func (s *SecureClient) makeRequest(req *http.Request) (*Response, error) {
	httpClient, err := s.HTTPClient()
	if err != nil {
		return nil, err
	}

	if req.URL.Host == "" {
		req.URL.Scheme = "https"
		req.URL.Host = s.Enclave()
	}

	// Require HTTPS to protect request headers as well as the body.
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("refusing to send request over non-https URL %q", req.URL.String())
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponse(resp)
}

// Post makes an HTTP POST request
func (s *SecureClient) Post(url string, headers map[string]string, body []byte) (*Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return s.makeRequest(req)
}

// Get makes an HTTP GET request
func (s *SecureClient) Get(url string, headers map[string]string) (*Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return s.makeRequest(req)
}

// SecureGet makes an HTTP GET request (gomobile-compatible: headers as JSON string)
func (s *SecureClient) SecureGet(url string, headersJSON string) (*Response, error) {
	headers, err := parseHeadersJSON(headersJSON)
	if err != nil {
		return nil, err
	}
	return s.Get(url, headers)
}

// SecurePost makes an HTTP POST request (gomobile-compatible: headers as JSON string)
func (s *SecureClient) SecurePost(url string, headersJSON string, body []byte) (*Response, error) {
	headers, err := parseHeadersJSON(headersJSON)
	if err != nil {
		return nil, err
	}
	return s.Post(url, headers, body)
}

func parseHeadersJSON(headersJSON string) (map[string]string, error) {
	if headersJSON == "" {
		return nil, nil
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		return nil, fmt.Errorf("failed to parse headers JSON: %v", err)
	}
	return headers, nil
}

// VerifyJSON verifies an enclave against a repo and returns the verification data as a JSON string
func VerifyJSON(enclave, repo string) (string, error) {
	client := NewSecureClient(enclave, repo)
	if _, err := client.Verify(); err != nil {
		return "", err
	}
	return client.GroundTruthJSON()
}
