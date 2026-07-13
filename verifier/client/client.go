package client

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

//go:embed trusted_root.json
var embeddedTrustedRoot []byte

// GroundTruth represents the "known good" state of the enclave
type GroundTruth struct {
	EnclaveHost         string                           `json:"enclave_host,omitempty"`
	TLSPublicKey        string                           `json:"tls_public_key,omitempty"`
	HPKEPublicKey       string                           `json:"hpke_public_key,omitempty"`
	Digest              string                           `json:"digest"`
	CodeMeasurement     *measurement.Measurement         `json:"code_measurement"`
	EnclaveMeasurement  *measurement.Measurement         `json:"enclave_measurement"`
	HardwareMeasurement *measurement.HardwareMeasurement `json:"hardware_measurement,omitempty"`
	CodeFingerprint     string                           `json:"code_fingerprint"`
	EnclaveFingerprint  string                           `json:"enclave_fingerprint"`
}

type SecureClient struct {
	enclave, repo string

	groundTruth    *GroundTruth
	sigstoreClient *provenance.Client
}

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
	defaultClient     = NewSecureClient("inference.tinfoil.sh", defaultRouterRepo)
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

// NewSecureClient creates a new secure client with a given repo and enclave
func NewSecureClient(enclave, repo string) *SecureClient {
	return &SecureClient{
		enclave: enclave,
		repo:    repo,
	}
}

// NewDefaultClient creates a new secure client with fallback mechanism.
// It tries to fetch routers from the router service, attempts to verify each one,
// and falls back to inference.tinfoil.sh if all routers fail.
func NewDefaultClient() (*SecureClient, error) {
	routers, err := fetchRouters()
	if err != nil {
		// If we can't get routers, fall back to inference.tinfoil.sh immediately
		return defaultClient, nil
	}

	// Try each router in sequence
	for _, routerURL := range routers {
		client := NewSecureClient(routerURL, defaultRouterRepo)

		// Return first working router
		_, err := client.Verify()
		if err == nil {
			return client, nil
		}
	}

	return defaultClient, nil
}

// Enclave returns the enclave URL
func (s *SecureClient) Enclave() string {
	return s.enclave
}

// Repo returns the repository URL
func (s *SecureClient) Repo() string {
	return s.repo
}

// GroundTruth returns the last verified enclave state
func (s *SecureClient) GroundTruth() *GroundTruth {
	return s.groundTruth
}

// GroundTruthJSON returns the ground truth as a JSON string
func (s *SecureClient) GroundTruthJSON() (string, error) {
	encoded, err := json.Marshal(s.groundTruth)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (s *SecureClient) getSigstoreClient() (*provenance.Client, error) {
	if s.sigstoreClient == nil {
		var err error
		s.sigstoreClient, err = getSigstoreClient(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create sigstore client: %v", err)
		}
	}
	return s.sigstoreClient, nil
}

// Verify attests the enclave with the v3 single-request flow and stores the
// resulting ground truth in the client.
func (s *SecureClient) Verify() (*GroundTruth, error) {
	if _, err := s.VerifyV3(); err != nil {
		return nil, err
	}
	return s.groundTruth, nil
}

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave
func (s *SecureClient) HTTPClient() (*http.Client, error) {
	if s.groundTruth == nil {
		_, err := s.Verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify enclave: %v", err)
		}
	}

	return &http.Client{
		Transport: &TLSBoundRoundTripper{ExpectedPublicKey: s.groundTruth.TLSPublicKey},
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
		req.URL.Host = s.enclave
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
func VerifyJSON(enclave, repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	sigstoreClient, err := getSigstoreClient(sigstoreTrustedRootJSON)
	if err != nil {
		return "", fmt.Errorf("failed to create sigstore client: %v", err)
	}

	client := &SecureClient{
		enclave:        enclave,
		repo:           repo,
		sigstoreClient: sigstoreClient,
	}
	_, err = client.Verify()
	if err != nil {
		return "", err
	}
	return client.GroundTruthJSON()
}

// getSigstoreClient builds a provenance client from the given trusted root,
// or from the embedded copy when nil. Sigstore verification never fetches
// its trust root over the network.
func getSigstoreClient(sigstoreTrustedRootJSON []byte) (*provenance.Client, error) {
	trustedRootJSON := sigstoreTrustedRootJSON
	if len(trustedRootJSON) == 0 {
		trustedRootJSON = embeddedTrustedRoot
	}
	return provenance.NewClientFromJSON(trustedRootJSON)
}
