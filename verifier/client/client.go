package client

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/measurement"
	"github.com/tinfoilsh/tinfoil-go/verifier/policy"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
	"github.com/tinfoilsh/tinfoil-go/verifier/util"
)

type SecureClient struct {
	enclave, repo string
	options       VerificationOptions

	stateMu    sync.RWMutex
	state      *VerifiedDocumentV3
	refreshing *verificationCall
	verify     func() (*VerifiedDocumentV3, error)
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

// VerificationOptions is copied at construction. Create a new client to change it.
type VerificationOptions struct {
	// PinnedRegisters adds register checks; empty entries retain defaults.
	PinnedRegisters *measurement.Measurement `json:"pinned_registers,omitempty"`
	// PinnedCode replaces code provenance with trusted release workload registers.
	// Requires an empty source repository and cannot be combined with PinnedRegisters.
	PinnedCode *measurement.CodeMeasurement `json:"pinned_code,omitempty"`
	// PinnedShape supplies the release's VM shape when PinnedCode targets TDX.
	PinnedShape *policy.Shape `json:"pinned_shape,omitempty"`
	// FreshnessMaxAge defaults to seven days when zero. Negative ages are invalid.
	FreshnessMaxAge time.Duration `json:"freshness_max_age_ns,omitempty"`
}

func (input *VerificationOptions) normalized(repo string) (VerificationOptions, error) {
	var opts VerificationOptions
	if input != nil {
		opts = *input
	}
	if opts.FreshnessMaxAge < 0 {
		return VerificationOptions{}, fmt.Errorf("freshness maximum age must not be negative")
	}
	opts.FreshnessMaxAge = cmp.Or(opts.FreshnessMaxAge, provenance.MaxFreshnessAge)
	opts.PinnedRegisters = cloneMeasurement(opts.PinnedRegisters)
	if opts.PinnedCode == nil {
		if opts.PinnedShape != nil {
			return VerificationOptions{}, fmt.Errorf("PinnedShape requires PinnedCode")
		}
		return opts, nil
	}
	if repo != "" {
		return VerificationOptions{}, fmt.Errorf("PinnedCode cannot be combined with a source repository")
	}
	if opts.PinnedRegisters != nil {
		return VerificationOptions{}, fmt.Errorf("PinnedCode cannot be combined with PinnedRegisters")
	}
	code, err := measurement.ValidateCode(opts.PinnedCode)
	if err != nil {
		return VerificationOptions{}, fmt.Errorf("invalid pinned code: %w", err)
	}
	opts.PinnedCode = code
	if opts.PinnedShape != nil {
		shape := *opts.PinnedShape
		if shape.CPUs < 0 || shape.MemoryMB < 0 || shape.Disks < 0 || shape.GPUs != nil && *shape.GPUs < 0 {
			return VerificationOptions{}, fmt.Errorf("pinned VM shape dimensions must be non-negative")
		}
		if shape.GPUs != nil {
			gpus := *shape.GPUs
			shape.GPUs = &gpus
		}
		opts.PinnedShape = &shape
	} else if code.TDXMeasurement != nil && code.SNPMeasurement == "" {
		return VerificationOptions{}, fmt.Errorf("a TDX workload pin requires PinnedShape")
	}
	return opts, nil
}

// NewSecureClient creates a secure client for an enclave and repository
// reference, owner/name[@tag][@sha256:digest]. Verification happens on first use.
func NewSecureClient(enclave, repo string, opts *VerificationOptions) (*SecureClient, error) {
	options, err := opts.normalized(repo)
	if err != nil {
		return nil, err
	}
	if options.PinnedCode != nil && enclave == "" {
		return nil, fmt.Errorf("PinnedCode requires an explicit enclave")
	}
	return &SecureClient{enclave: enclave, repo: repo, options: options}, nil
}

// NewDefaultClient applies opts to every discovered router and fallback.
func NewDefaultClient(opts *VerificationOptions) (*SecureClient, error) {
	if opts != nil && opts.PinnedCode != nil {
		return nil, fmt.Errorf("PinnedCode requires an explicit enclave")
	}
	fallback, err := NewSecureClient("inference.tinfoil.sh", defaultRouterRepo, opts)
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

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave
func (s *SecureClient) HTTPClient() (*http.Client, error) {
	transport, err := s.NewTransport(func(verified *VerifiedDocumentV3) (http.RoundTripper, error) {
		key, err := verified.TLSPublicKeyFP()
		if err != nil {
			return nil, err
		}
		return &TLSBoundRoundTripper{ExpectedPublicKey: key}, nil
	}, isCertificateError)
	if err != nil {
		return nil, fmt.Errorf("creating TLS transport: %w", err)
	}
	return &http.Client{Transport: transport}, nil
}

// Request sends an HTTPS request. headersJSON is a JSON object or empty.
func (s *SecureClient) Request(method, url, headersJSON string, body []byte) (*Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if headersJSON != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			return nil, err
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
		return nil, fmt.Errorf("refusing to send request over non-https URL %q", req.URL.String())
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	return toResponse(resp)
}
