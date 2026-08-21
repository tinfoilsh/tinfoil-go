package client

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/github"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

const (
	pinnedNoRepo   = "pinned_no_repo"
	pinnedNoDigest = "pinned_no_digest"
)

//go:embed trusted_root.json
var embeddedTrustedRoot []byte

// GroundTruth represents the "known good" state of the enclave
type GroundTruth struct {
	ConfigRepo          string                           `json:"config_repo,omitempty"`
	EnclaveHost         string                           `json:"enclave_host,omitempty"`
	ReleaseTag          string                           `json:"release_tag,omitempty"`
	TLSPublicKey        string                           `json:"tls_public_key,omitempty"`
	HPKEPublicKey       string                           `json:"hpke_public_key,omitempty"`
	Digest              string                           `json:"digest"`
	CodeMeasurement     *attestation.Measurement         `json:"code_measurement"`
	EnclaveMeasurement  *attestation.Measurement         `json:"enclave_measurement"`
	HardwareMeasurement *attestation.HardwareMeasurement `json:"hardware_measurement,omitempty"`
	CodeFingerprint     string                           `json:"code_fingerprint"`
	EnclaveFingerprint  string                           `json:"enclave_fingerprint"`
	Verifier            SoftwareIdentity                 `json:"verifier"`
	VerifiedAt          string                           `json:"verified_at"`
	DigestFetched       bool                             `json:"-"`
}

type secureClientConfig struct {
	// enclave is an optional caller constraint. An empty value delegates router
	// selection to the attestation bundle service.
	enclave string
	repo    string
}

type SecureClient struct {
	// config is immutable caller intent. The selected/verified endpoint lives in
	// groundTruth, so discovery never overwrites configuration.
	config secureClientConfig

	// When set, Verify fetches a pre-assembled attestation bundle from
	// {attestationBundleURL}/attestation and verifies it client-side instead of
	// attesting the enclave directly. This lets attestation traffic flow through
	// a proxy so the client only needs to reach a single origin.
	attestationBundleURL string

	// Pinned measurement mode
	codeMeasurement      *attestation.Measurement
	hardwareMeasurements []*attestation.HardwareMeasurement

	groundTruth          *GroundTruth
	verificationDocument *VerificationDocument
	stateMu              sync.RWMutex
	verifyMu             sync.Mutex
	sigstoreClient       *sigstore.Client
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

// NewSecureClient creates a new secure client with a given repo and enclave
func NewSecureClient(enclave, repo string) *SecureClient {
	return &SecureClient{
		config: secureClientConfig{enclave: enclave, repo: repo},
	}
}

// NewPinnedSecureClient creates a new secure client with a given enclave and fixed measurements
func NewPinnedSecureClient(enclave string, codeMeasurement *attestation.Measurement, hardwareMeasurements []*attestation.HardwareMeasurement) *SecureClient {
	return &SecureClient{
		config:               secureClientConfig{enclave: enclave, repo: pinnedNoRepo},
		codeMeasurement:      codeMeasurement,
		hardwareMeasurements: hardwareMeasurements,
	}
}

// NewDefaultClient asks ATC for eligible routers and returns the first one that
// passes verification. Discovery fails closed: the SDK never substitutes a
// hard-coded router when ATC is unavailable or all advertised routers fail.
func NewDefaultClient() (*SecureClient, error) {
	routers, err := fetchRouters()
	if err != nil {
		return nil, fmt.Errorf("fetch routers from ATC: %w", err)
	}

	var lastErr error
	for _, routerURL := range routers {
		client := NewSecureClient(routerURL, defaultRouterRepo)
		_, err = client.Verify()
		if err == nil {
			return client, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, fmt.Errorf("no ATC router passed verification: %w", lastErr)
	}
	return nil, fmt.Errorf("ATC returned no routers")
}

// Enclave returns the enclave URL
func (s *SecureClient) Enclave() string {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if s.groundTruth != nil && s.groundTruth.EnclaveHost != "" {
		return s.groundTruth.EnclaveHost
	}
	return s.config.enclave
}

// Repo returns the repository URL
func (s *SecureClient) Repo() string {
	return s.config.repo
}

// SetAttestationBundleURL configures the client to fetch and verify a
// pre-assembled attestation bundle from {url}/attestation instead of attesting
// the enclave directly. Pass an empty string to restore direct attestation.
func (s *SecureClient) SetAttestationBundleURL(url string) {
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	s.attestationBundleURL = url
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

// VerificationDocument returns the last successful Verification Center-compatible result.
func (s *SecureClient) VerificationDocument() *VerificationDocument {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return cloneVerificationDocument(s.verificationDocument)
}

// VerificationDocumentJSON returns the last successful verification document as JSON.
func (s *SecureClient) VerificationDocumentJSON() (string, error) {
	encoded, err := json.Marshal(s.VerificationDocument())
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (s *SecureClient) getSigstoreClient() (*sigstore.Client, error) {
	if s.sigstoreClient == nil {
		var err error
		s.sigstoreClient, err = sigstore.NewClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create sigstore client: %v", err)
		}
	}
	return s.sigstoreClient, nil
}

// Verify fetches the latest verification information from GitHub and Sigstore and stores the ground truth results in the client
func (s *SecureClient) Verify() (*GroundTruth, error) {
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()

	// When an attestation bundle URL is configured, attest from the bundle so
	// the enclave does not need to be reached directly (proxy-friendly).
	if s.attestationBundleURL != "" {
		// A pinned measurement and an attestation bundle are mutually exclusive
		// verification methods: the bundle carries its own code measurement, so
		// honoring a pinned measurement would be ambiguous.
		if s.codeMeasurement != nil {
			return nil, fmt.Errorf("cannot combine a pinned measurement with an attestation bundle URL")
		}
		// Ask the bundle service for the caller-configured enclave when one was
		// supplied. Do not reuse an endpoint discovered from a previous default
		// bundle: after an HPKE mismatch, recovery must be able to fetch a fresh
		// default bundle and rotate the entire endpoint/key pair, matching the JS
		// SDK's reset semantics.
		enclaveURL, repo := s.bundleRequestParameters()
		bundle, err := attestation.FetchBundleFor(s.attestationBundleURL, enclaveURL, repo)
		if err != nil {
			return nil, fmt.Errorf("fetchBundle: failed to fetch attestation bundle: %v", err)
		}
		return s.verifyFromBundle(bundle)
	}

	var codeMeasurement = s.codeMeasurement
	var digest = pinnedNoDigest
	var releaseTag string
	if s.codeMeasurement == nil {
		release, err := github.FetchLatestRelease(s.config.repo)
		if err != nil {
			return nil, fmt.Errorf("fetchDigest: failed to fetch latest release: %v", err)
		}
		digest = release.Digest
		releaseTag = release.Tag

		sigstoreClient, err := s.getSigstoreClient()
		if err != nil {
			return nil, fmt.Errorf("verifyCode: failed to create sigstore client: %v", err)
		}

		sigstoreBundle, err := github.FetchAttestationBundle(s.config.repo, digest)
		if err != nil {
			return nil, fmt.Errorf("verifyCode: failed to fetch attestation bundle: %v", err)
		}

		codeMeasurement, err = sigstoreClient.VerifyAttestationForRelease(sigstoreBundle, s.config.repo, releaseTag, digest)
		if err != nil {
			return nil, fmt.Errorf("verifyCode: failed to verify attested measurements: %v", err)
		}
	}

	enclaveAttestation, err := attestation.Fetch(s.config.enclave)
	if err != nil {
		return nil, fmt.Errorf("verifyEnclave: failed to fetch enclave measurements: %v", err)
	}
	enclaveVerification, err := enclaveAttestation.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifyEnclave: failed to verify enclave measurements: %v", err)
	}

	// Fetch hardware platform measurements if required
	var matchedHwMeasurement *attestation.HardwareMeasurement
	if enclaveAttestation.Format == attestation.TdxGuestV2 {
		var hwMeasurements = s.hardwareMeasurements
		if len(s.hardwareMeasurements) == 0 {
			sigstoreClient, err := s.getSigstoreClient()
			if err != nil {
				return nil, fmt.Errorf("verifyHardware: failed to create sigstore client: %v", err)
			}
			hwMeasurements, err = sigstoreClient.LatestHardwareMeasurements()
			if err != nil {
				return nil, fmt.Errorf("verifyHardware: failed to fetch TDX platform measurements: %v", err)
			}
		}

		matchedHwMeasurement, err = attestation.VerifyHardware(hwMeasurements, enclaveVerification.Measurement)
		if err != nil {
			return nil, fmt.Errorf("verifyHardware: failed to verify hardware measurements: %v", err)
		}
	}

	if err := enclaveValidPubKey(s.config.enclave, enclaveVerification); err != nil {
		return nil, fmt.Errorf("validateTLS: %v", err)
	}

	if err = codeMeasurement.Equals(enclaveVerification.Measurement); err != nil {
		return nil, fmt.Errorf("measurements: %v", err)
	}

	codeFingerprint, err := attestation.Fingerprint(codeMeasurement, matchedHwMeasurement, enclaveVerification.Measurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute code fingerprint: %v", err)
	}
	enclaveFingerprint, err := attestation.Fingerprint(enclaveVerification.Measurement, matchedHwMeasurement, enclaveVerification.Measurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute enclave fingerprint: %v", err)
	}

	groundTruth := &GroundTruth{
		ConfigRepo:          s.config.repo,
		EnclaveHost:         s.config.enclave,
		ReleaseTag:          releaseTag,
		TLSPublicKey:        enclaveVerification.TLSPublicKeyFP,
		HPKEPublicKey:       enclaveVerification.HPKEPublicKey,
		Digest:              digest,
		HardwareMeasurement: matchedHwMeasurement,
		CodeMeasurement:     codeMeasurement,
		EnclaveMeasurement:  enclaveVerification.Measurement,
		CodeFingerprint:     codeFingerprint,
		EnclaveFingerprint:  enclaveFingerprint,
		Verifier:            currentVerifierIdentity(),
		VerifiedAt:          verificationTime().UTC().Format(time.RFC3339Nano),
		DigestFetched:       s.codeMeasurement == nil,
	}
	s.setVerifiedState(groundTruth)
	return groundTruth, nil
}

// bundleRequestParameters returns only caller-provided routing constraints.
// In particular, it never turns an enclave discovered from a default bundle
// into a pinned request parameter: recovery must remain free to select a fresh
// default router and its matching HPKE key.
func (s *SecureClient) bundleRequestParameters() (enclaveURL, repo string) {
	if s.config.enclave != "" {
		enclaveURL = "https://" + s.config.enclave
	}
	if s.config.repo != defaultRouterRepo {
		repo = s.config.repo
	}
	return enclaveURL, repo
}

// VerifyFromBundle verifies using a pre-fetched attestation bundle (single-request verification)
func (s *SecureClient) VerifyFromBundle(bundle *attestation.Bundle) (*GroundTruth, error) {
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	return s.verifyFromBundle(bundle)
}

func (s *SecureClient) verifyFromBundle(bundle *attestation.Bundle) (*GroundTruth, error) {
	if err := s.validateBundleDomain(bundle.Domain); err != nil {
		return nil, err
	}

	sigstoreClient, err := s.getSigstoreClient()
	if err != nil {
		return nil, fmt.Errorf("verifyCode: failed to create sigstore client: %v", err)
	}

	var codeMeasurement *attestation.Measurement
	if bundle.ReleaseTag != "" {
		codeMeasurement, err = sigstoreClient.VerifyAttestationForRelease(
			bundle.SigstoreBundle, s.config.repo, bundle.ReleaseTag, bundle.Digest,
		)
	} else {
		codeMeasurement, err = sigstoreClient.VerifyAttestation(bundle.SigstoreBundle, s.config.repo, bundle.Digest)
	}
	if err != nil {
		return nil, fmt.Errorf("verifyCode: failed to verify attested measurements: %v", err)
	}

	// Decode VCEK from base64 DER format
	vcekDER, err := base64.StdEncoding.DecodeString(bundle.VCEK)
	if err != nil {
		return nil, fmt.Errorf("verifyEnclave: failed to decode VCEK certificate: %v", err)
	}

	enclaveVerification, err := bundle.EnclaveAttestationReport.VerifyWithVCEK(vcekDER)
	if err != nil {
		return nil, fmt.Errorf("verifyEnclave: failed to verify enclave measurements: %v", err)
	}

	if err = codeMeasurement.Equals(enclaveVerification.Measurement); err != nil {
		return nil, fmt.Errorf("measurements: %v", err)
	}

	codeFingerprint, err := attestation.Fingerprint(codeMeasurement, nil, enclaveVerification.Measurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute code fingerprint: %v", err)
	}
	enclaveFingerprint, err := attestation.Fingerprint(enclaveVerification.Measurement, nil, enclaveVerification.Measurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute enclave fingerprint: %v", err)
	}

	// Verify enclave certificate
	if bundle.EnclaveCert == "" {
		return nil, fmt.Errorf("verifyCertificate: enclave certificate is required")
	}
	_, err = attestation.VerifyCertificate(
		bundle.EnclaveCert,
		bundle.Domain,
		bundle.EnclaveAttestationReport,
		enclaveVerification.HPKEPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("verifyCertificate: %v", err)
	}

	groundTruth := &GroundTruth{
		ConfigRepo:         s.config.repo,
		EnclaveHost:        bundle.Domain,
		ReleaseTag:         bundle.ReleaseTag,
		TLSPublicKey:       enclaveVerification.TLSPublicKeyFP,
		HPKEPublicKey:      enclaveVerification.HPKEPublicKey,
		Digest:             bundle.Digest,
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: enclaveVerification.Measurement,
		CodeFingerprint:    codeFingerprint,
		EnclaveFingerprint: enclaveFingerprint,
		Verifier:           currentVerifierIdentity(),
		VerifiedAt:         verificationTime().UTC().Format(time.RFC3339Nano),
	}
	s.setVerifiedState(groundTruth)
	return groundTruth, nil
}

func (s *SecureClient) validateBundleDomain(domain string) error {
	if s.config.enclave != "" && domain != s.config.enclave {
		return fmt.Errorf("verifyBundle: domain %q does not match configured enclave %q", domain, s.config.enclave)
	}
	return nil
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

	// Request headers may carry the API key, so never send them over a plaintext
	// connection.
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

	client := NewSecureClient(enclave, repo)
	client.sigstoreClient = sigstoreClient
	_, err = client.Verify()
	if err != nil {
		return "", err
	}
	return client.GroundTruthJSON()
}

func getSigstoreClient(sigstoreTrustedRootJSON []byte) (*sigstore.Client, error) {
	var trustedRootJSON []byte
	var err error

	if len(sigstoreTrustedRootJSON) > 0 {
		trustedRootJSON = sigstoreTrustedRootJSON
	} else if len(embeddedTrustedRoot) > 0 {
		trustedRootJSON = embeddedTrustedRoot
	} else {
		trustedRootJSON, err = sigstore.FetchTrustRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch trusted root: %v", err)
		}
	}

	return sigstore.NewClientFromJSON(trustedRootJSON)
}

func verifyBundle(bundle *attestation.Bundle, repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	sigstoreClient, err := getSigstoreClient(sigstoreTrustedRootJSON)
	if err != nil {
		return "", fmt.Errorf("failed to create sigstore client: %v", err)
	}

	client := NewSecureClient(bundle.Domain, repo)
	client.sigstoreClient = sigstoreClient
	_, err = client.VerifyFromBundle(bundle)
	if err != nil {
		return "", err
	}
	return client.GroundTruthJSON()
}

// VerifyFromBundleJSON verifies using a pre-fetched attestation bundle and returns the verification data as a JSON string
func VerifyFromBundleJSON(bundleJSON []byte, repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	var bundle attestation.Bundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return "", fmt.Errorf("failed to parse bundle: %v", err)
	}
	return verifyBundle(&bundle, repo, sigstoreTrustedRootJSON)
}

// FetchAndVerifyJSON fetches an attestation bundle from the default endpoint and verifies it.
// Returns the verification data as a JSON string.
func FetchAndVerifyJSON(repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	return FetchAndVerifyFromURLJSON("", repo, sigstoreTrustedRootJSON)
}

// FetchAndVerifyFromURLJSON fetches an attestation bundle from a custom URL and verifies it.
// If attestationBundleURL is empty, defaults to the Tinfoil bundle endpoint.
// Returns the verification data as a JSON string.
func FetchAndVerifyFromURLJSON(attestationBundleURL, repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	var bundle *attestation.Bundle
	var err error

	if attestationBundleURL == "" {
		bundle, err = attestation.FetchBundle()
	} else {
		bundle, err = attestation.FetchBundleFrom(attestationBundleURL)
	}
	if err != nil {
		return "", fmt.Errorf("failed to fetch bundle: %v", err)
	}

	return verifyBundle(bundle, repo, sigstoreTrustedRootJSON)
}
