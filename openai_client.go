package tinfoil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
)

// Client wraps the OpenAI client with verification for secure enclaves
type Client struct {
	*openai.Client
	enclave     string
	repo        string
	groundTruth *GroundTruth
}

// NewClient creates a new secure OpenAI client that verifies the enclave
func NewClient(enclave, repo string, openaiOpts ...option.RequestOption) (*Client, error) {
	// Use provided parameters or fall back to environment variables
	if enclave == "" {
		enclave = getEnvDefault("TINFOIL_ENCLAVE", "")
	}

	if repo == "" {
		repo = getEnvDefault("TINFOIL_REPO", "")
	}

	if enclave == "" || repo == "" {
		return nil, fmt.Errorf("tinfoil: enclave and repo must be specified")
	}

	client := &Client{
		enclave: enclave,
		repo:    repo,
	}

	// Create the OpenAI client with secure connection
	openaiClient, err := client.createOpenAIClient(openaiOpts...)
	if err != nil {
		return nil, err
	}

	client.Client = openaiClient
	return client, nil
}

// createOpenAIClient sets up the OpenAI client with a secure HTTP client
func (c *Client) createOpenAIClient(opts ...option.RequestOption) (*openai.Client, error) {
	// Verify the enclave and get the certificate fingerprint
	secureClient := NewSecureClient(c.enclave, c.repo)
	// Verify enclave and repo
	groundTruth, err := secureClient.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify enclave: %w", err)
	}
	c.groundTruth = groundTruth

	// Create a custom transport that verifies certificate fingerprints
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("no certificate found")
				}

				// Calculate the SHA-256 fingerprint of the certificate
				certFingerprint := sha256.Sum256(rawCerts[0])

				// Compare with the expected fingerprint from attestation
				if !equalBytes(certFingerprint[:], c.groundTruth.CertFingerprint) {
					return fmt.Errorf("certificate fingerprint mismatch")
				}

				return nil
			},
		},
	}

	// Create an HTTP client with our custom transport
	httpClient := &http.Client{
		Transport: transport,
	}

	// Add our HTTP client and base URL to the options
	allOpts := append(opts,
		option.WithHTTPClient(httpClient),
		option.WithBaseURL(fmt.Sprintf("https://%s/v1/", c.enclave)),
	)

	// Create the OpenAI client with our custom HTTP client
	client := openai.NewClient(allOpts...)

	return client, nil
}
