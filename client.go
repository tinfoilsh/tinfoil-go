package tinfoil

import (
	"fmt"
	"net/http"
	"os"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

// GroundTruth represents the "known good" verified state of the enclave
type GroundTruth struct {
	PublicKeyFP string
	Digest      string
	Measurement string
}

// SecureClient provides a way to securely communicate with a verified enclave
type SecureClient struct {
	enclave, repo string
	groundTruth   *GroundTruth
}

// NewSecureClient creates a new client for secure communications with the enclave using default parameters
func NewSecureClient() *SecureClient {
	return NewSecureClientWithParams("inference.tinfoil.sh", "tinfoilsh/confidential-inference-proxy")
}

// NewSecureClientWithParams creates a new client for secure communications with the enclave using custom parameters
func NewSecureClientWithParams(enclave, repo string) *SecureClient {
	return &SecureClient{
		enclave: enclave,
		repo:    repo,
	}
}

// GroundTruth returns the last verified enclave state
func (s *SecureClient) GroundTruth() *GroundTruth {
	return s.groundTruth
}

// Verify fetches the latest verification information from GitHub and Sigstore and stores the ground truth results in the client
func (s *SecureClient) Verify() (*GroundTruth, error) {
	digest, err := github.FetchLatestDigest(s.repo)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest release: %v", err)
	}

	sigstoreBundle, err := github.FetchAttestationBundle(s.repo, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestation bundle: %v", err)
	}

	trustRootJSON, err := sigstore.FetchTrustRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch trust root: %v", err)
	}

	codeMeasurements, err := sigstore.VerifyAttestation(trustRootJSON, sigstoreBundle, digest, s.repo)
	if err != nil {
		return nil, fmt.Errorf("failed to verify attested measurements: %v", err)
	}

	enclaveAttestation, err := attestation.Fetch(s.enclave)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch enclave measurements: %v", err)
	}
	verification, err := enclaveAttestation.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify enclave measurements: %v", err)
	}

	err = codeMeasurements.Equals(verification.Measurement)
	if err == nil {
		s.groundTruth = &GroundTruth{
			PublicKeyFP: verification.PublicKeyFP,
			Digest:      digest,
			Measurement: codeMeasurements.Fingerprint(),
		}
	}
	return s.groundTruth, err
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
		Transport: &TLSBoundRoundTripper{ExpectedPublicKey: s.groundTruth.PublicKeyFP},
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

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponse(resp)
}

// Helper function to get environment variable with default
func getEnvDefault(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}
