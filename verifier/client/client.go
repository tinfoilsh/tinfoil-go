package client

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
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
	enclave, repo       string
	verificationOptions VerificationOptions

	groundTruth          *GroundTruth
	verificationDocument *VerificationDocument
	stateMu              sync.RWMutex
	verifyMu             sync.Mutex
}

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
)

func newFallbackClient() *SecureClient {
	return NewSecureClient("inference.tinfoil.sh", defaultRouterRepo)
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
	return &SecureClient{
		enclave: enclave,
		repo:    repo,
	}
}

// NewSecureClientWithOptions creates a client with caller-owned verification
// policy. A zero options value preserves the defaults.
func NewSecureClientWithOptions(enclave, repo string, opts VerificationOptions) (*SecureClient, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	s := NewSecureClient(enclave, repo)
	s.verificationOptions = opts
	return s, nil
}

// NewDefaultClient creates a new secure client with fallback mechanism.
// It tries to fetch routers from the router service, attempts to verify each one,
// and falls back to inference.tinfoil.sh if all routers fail.
func NewDefaultClient() (*SecureClient, error) {
	return NewDefaultClientWithOptions(VerificationOptions{})
}

// NewDefaultClientWithOptions applies the same caller policy during router
// selection and subsequent verification, including the fallback enclave.
func NewDefaultClientWithOptions(opts VerificationOptions) (*SecureClient, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	fallback := func() (*SecureClient, error) {
		return NewSecureClientWithOptions("inference.tinfoil.sh", defaultRouterRepo, opts)
	}
	routers, err := fetchRouters()
	if err != nil {
		// If we can't get routers, fall back to inference.tinfoil.sh immediately
		return fallback()
	}

	// Try each router in sequence
	for _, routerURL := range routers {
		client, err := NewSecureClientWithOptions(routerURL, defaultRouterRepo, opts)
		if err != nil {
			return nil, err
		}

		// Return first working router
		_, err = client.Verify()
		if err == nil {
			return client, nil
		}
	}

	return fallback()
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

// SetExpectedRTMR3 sets the expected 48-byte hexadecimal runtime register.
// Empty requires an unextended register. Malformed values fail verification.
// This invalidates cached verification; previously returned HTTP clients keep
// their existing transport and should be replaced by the caller.
func (s *SecureClient) SetExpectedRTMR3(rtmr3 string) {
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	s.verificationOptions.ExpectedRTMR3 = rtmr3
	s.invalidateVerification()
}

// SetFreshnessMaxAge sets a positive maximum witness age and invalidates
// cached verification. Previously returned HTTP clients retain their transport.
func (s *SecureClient) SetFreshnessMaxAge(maxAge time.Duration) error {
	if maxAge <= 0 {
		return fmt.Errorf("freshness maximum age must be positive")
	}
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	s.verificationOptions.FreshnessMaxAge = maxAge
	s.invalidateVerification()
	return nil
}

// SetFreshnessMaxAgeSeconds is the mobile-compatible form of SetFreshnessMaxAge.
func (s *SecureClient) SetFreshnessMaxAgeSeconds(seconds int64) error {
	if seconds <= 0 || seconds > math.MaxInt64/int64(time.Second) {
		return fmt.Errorf("freshness maximum age seconds is out of range")
	}
	return s.SetFreshnessMaxAge(time.Duration(seconds) * time.Second)
}

func (s *SecureClient) invalidateVerification() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.groundTruth = nil
	s.verificationDocument = nil
}

// GroundTruth returns the last verified enclave state
func (s *SecureClient) GroundTruth() *GroundTruth {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return cloneGroundTruth(s.groundTruth)
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
	return cloneVerificationDocument(s.verificationDocument)
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
	groundTruth := s.GroundTruth()
	if groundTruth == nil {
		_, err := s.Verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify enclave: %v", err)
		}
		groundTruth = s.GroundTruth()
	}

	return &http.Client{
		Transport: &TLSBoundRoundTripper{ExpectedPublicKey: groundTruth.TLSPublicKey},
	}, nil
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
