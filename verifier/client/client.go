package client

import (
	"bytes"
	"context"
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

// GroundTruth represents the "known good" state of the enclave
type GroundTruth struct {
	ConfigRepo          string                           `json:"config_repo,omitempty"`
	EnclaveHost         string                           `json:"enclave_host,omitempty"`
	ReleaseTag          string                           `json:"release_tag,omitempty"`
	TLSPublicKey        string                           `json:"tls_public_key,omitempty"`
	HPKEPublicKey       string                           `json:"hpke_public_key,omitempty"`
	Digest              string                           `json:"digest"`
	CodeMeasurement     *measurement.Measurement         `json:"code_measurement"`
	EnclaveMeasurement  *measurement.Measurement         `json:"enclave_measurement"`
	HardwareMeasurement *measurement.HardwareMeasurement `json:"hardware_measurement,omitempty"`
	CodeFingerprint     string                           `json:"code_fingerprint"`
	EnclaveFingerprint  string                           `json:"enclave_fingerprint"`
	Verifier            SoftwareIdentity                 `json:"verifier"`
	VerifiedAt          string                           `json:"verified_at"`
	DigestFetched       bool                             `json:"-"`
}

type SecureClient struct {
	enclave, repo   string
	freshnessMaxAge time.Duration

	stateMu    sync.RWMutex
	state      *verificationState
	refreshing *verificationCall
	verify     func(context.Context) (*verificationState, error)
}

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
)

func newFallbackClient(maxAge time.Duration) *SecureClient {
	return newSecureClient("inference.tinfoil.sh", defaultRouterRepo, maxAge)
}

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

// NewSecureClient creates a new secure client with a given repo and enclave
func NewSecureClient(enclave, repo string) *SecureClient {
	return newSecureClient(enclave, repo, provenance.MaxFreshnessAge)
}

// NewSecureClientWithOptions copies policy before any verification takes place.
func NewSecureClientWithOptions(enclave, repo string, options VerificationOptions) (*SecureClient, error) {
	maxAge, err := options.freshnessMaxAge()
	if err != nil {
		return nil, err
	}
	return newSecureClient(enclave, repo, maxAge), nil
}

func newSecureClient(enclave, repo string, maxAge time.Duration) *SecureClient {
	return &SecureClient{
		enclave:         enclave,
		repo:            repo,
		freshnessMaxAge: maxAge,
	}
}

// NewDefaultClient creates a new secure client with fallback mechanism.
// It tries to fetch routers from the router service, attempts to verify each one,
// and falls back to inference.tinfoil.sh if all routers fail.
func NewDefaultClient() (*SecureClient, error) {
	return NewDefaultClientWithOptions(VerificationOptions{})
}

// NewDefaultClientWithOptions applies the same policy to every router candidate
// and the fallback, including their initial verification.
func NewDefaultClientWithOptions(options VerificationOptions) (*SecureClient, error) {
	maxAge, err := options.freshnessMaxAge()
	if err != nil {
		return nil, err
	}
	routers, err := fetchRouters()
	if err != nil {
		// If we can't get routers, fall back to inference.tinfoil.sh immediately
		return newFallbackClient(maxAge), nil
	}

	// Try each router in sequence
	for _, routerURL := range routers {
		client := newSecureClient(routerURL, defaultRouterRepo, maxAge)

		// Return first working router
		_, err := client.Verify()
		if err == nil {
			return client, nil
		}
	}

	return newFallbackClient(maxAge), nil
}

// Enclave returns the enclave URL
func (s *SecureClient) Enclave() string {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.enclave
}

// Repo returns the repository URL
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
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if s.state == nil {
		return nil
	}
	return cloneVerificationDocument(s.state.document)
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

	// If URL doesn't start with anything, assume it's a relative path and set the base URL
	if req.URL.Host == "" {
		req.URL.Scheme = "https"
		req.URL.Host = s.Enclave()
	}

	// Request headers (which may carry the API key) are not encrypted, so never
	// send them over a plaintext connection.
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
