// Package enclave connects to attested enclaves. A Handle fetches and verifies
// one enclave's attestation, keeps the result until it expires, and binds HTTP
// traffic to the keys the enclave endorses.
package enclave

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/measurement"
)

// Handle is the client-side handle for one attested enclave. It verifies the
// enclave's attestation on first use, verifies again when the result expires or
// the enclave rejects its keys, and hands out HTTP clients and transports bound
// to the verified keys. Everything it hands out shares one verification and one
// refresh.
type Handle struct {
	enclave, repo, relay string
	// verifier is the immutable verification policy, shared by every handle
	// derived from this one.
	verifier     *verify.Verifier
	configPolicy *verify.ConfigPolicy

	stateMu      sync.RWMutex
	state        *enclaveState
	refreshing   *verificationCall
	tlsTransport *clientTransport
	verify       func() (*verify.Verification, error)
}

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
)

const (
	routerFetchTimeout = 30 * time.Second
	maxRouterBytes     = 32 << 20
)

// fetchRouters is bounded the same way attestation fetching is: discovery runs
// before anything is verified, so an unresponsive or oversized reply must not
// stall client construction or exhaust memory.
func fetchRouters() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routerFetchTimeout)
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
		return nil, fmt.Errorf("fetching routers from %s: %d %s", defaultRouterURL, resp.StatusCode, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRouterBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRouterBytes {
		return nil, fmt.Errorf("router list from %s exceeds %d bytes", defaultRouterURL, maxRouterBytes)
	}

	var routers []string
	if err := json.Unmarshal(body, &routers); err != nil {
		return nil, err
	}

	return routers, nil
}

// Options is copied at construction. Create a new client to change it.
type Options struct {
	// PinnedRegisters adds register checks; empty entries retain defaults.
	PinnedRegisters *measurement.Measurement `json:"pinned_registers,omitempty"`
	// FreshnessMaxAge defaults to seven days when zero. Negative ages are invalid.
	FreshnessMaxAge time.Duration `json:"freshness_max_age_ns,omitempty"`
}

// verifier builds the immutable policy these options describe, validating
// them once. A nil receiver selects the defaults.
func (input *Options) verifier(extra ...verify.Option) (*verify.Verifier, error) {
	if input == nil {
		return verify.NewVerifier(extra...)
	}
	opts := []verify.Option{
		verify.WithPinnedRegisters(input.PinnedRegisters),
		verify.WithFreshnessMaxAge(input.FreshnessMaxAge),
	}
	return verify.NewVerifier(append(opts, extra...)...)
}

// NewHandle creates a handle for an enclave and repository
// reference, owner/name[@tag][@sha256:digest]. Verification happens on first use.
func NewHandle(enclave, repo string, opts *Options) (*Handle, error) {
	if _, _, _, err := verify.ParseReference(repo); err != nil {
		return nil, &ConfigurationError{Err: err}
	}
	verifier, err := opts.verifier()
	if err != nil {
		return nil, err
	}
	return &Handle{enclave: enclave, repo: repo, verifier: verifier}, nil
}

// NewConfigHandle requires the IGVM config-binding profile. Nil keys select
// Tinfoil's public config signer; explicit keys replace that trust for private configs.
func NewConfigHandle(enclave string, policy verify.ConfigPolicy, keys []crypto.PublicKey, opts *Options) (*Handle, error) {
	if err := policy.Validate(); err != nil {
		return nil, &ConfigurationError{Err: err}
	}
	var trust []verify.Option
	if keys != nil {
		trust = append(trust, verify.WithConfigSigningKeys(keys))
	}
	verifier, err := opts.verifier(trust...)
	if err != nil {
		return nil, err
	}
	return &Handle{enclave: enclave, verifier: verifier, configPolicy: &policy}, nil
}

// NewDefaultHandle applies opts to every discovered router and fallback.
func NewDefaultHandle(opts *Options) (*Handle, error) {
	fallback, err := NewHandle("inference.tinfoil.sh", defaultRouterRepo, opts)
	if err != nil {
		return nil, err
	}
	routers, _ := fetchRouters()
	for _, routerURL := range routers {
		client := fallback.ForEnclave(routerURL)
		_, err := client.verifiedState(context.Background(), true, candidateVerificationRetries)
		if err == nil {
			return client, nil
		}
	}

	return fallback, nil
}

// ForEnclave keeps the repository reference and verification options.
func (s *Handle) ForEnclave(enclave string) *Handle {
	return &Handle{enclave: enclave, repo: s.repo, verifier: s.verifier, configPolicy: s.configPolicy}
}

// ViaRelay fetches attestation through relay, which forwards it to the enclave.
func (s *Handle) ViaRelay(relay string) *Handle {
	return &Handle{enclave: s.enclave, repo: s.repo, relay: relay, verifier: s.verifier, configPolicy: s.configPolicy}
}

// Enclave returns the enclave URL
func (s *Handle) Enclave() string {
	return s.enclave
}

// Repo returns the trusted repository reference, including any tag or digest pins.
func (s *Handle) Repo() string {
	return s.repo
}

// Verification returns a copy of the last verified enclave state.
func (s *Handle) Verification() *verify.Verification {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if s.state == nil {
		return nil
	}
	return cloneVerification(s.state.Verification)
}

// VerificationJSON returns the last verification as JSON.
func (s *Handle) VerificationJSON() (string, error) {
	encoded, err := json.Marshal(s.Verification())
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave
func (s *Handle) HTTPClient() (*http.Client, error) {
	s.stateMu.Lock()
	if s.tlsTransport == nil {
		s.tlsTransport = &clientTransport{client: s, build: func(verified *verify.Verification) (http.RoundTripper, error) {
			key, err := verified.TLSPublicKeyFP()
			if err != nil {
				return nil, err
			}
			return &TLSBoundRoundTripper{ExpectedPublicKey: key}, nil
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
func (s *Handle) Request(method, url, headersJSON string, body []byte) (result *Response, err error) {
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
