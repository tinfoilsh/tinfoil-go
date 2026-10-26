// Package enclave connects to attested enclaves. A Handle fetches and verifies
// one enclave's attestation, keeps the result until it expires, and binds HTTP
// traffic to the keys the enclave endorses.
package enclave

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document/collateral"
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
	verifier *verify.Verifier

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
func fetchRouters(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, routerFetchTimeout)
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
	// EmbeddedConfig trusts exact caller-supplied bytes instead of a config endorsement.
	EmbeddedConfig *verify.EmbeddedConfig
	// ConfigAuthorizer authorizes document-carried configs instead of their endorsement.
	ConfigAuthorizer func(collateral.ConfigEndorsement) error
	// PinnedRegisters adds register checks (see verify.WithPinnedRegisters).
	PinnedRegisters measurement.Expected
	// FreshnessMaxAge defaults to seven days when zero. Negative ages are invalid.
	FreshnessMaxAge time.Duration
}

// Verifier builds the immutable policy these options describe, validating
// them once. A nil receiver selects the defaults.
func (input *Options) Verifier() (*verify.Verifier, error) {
	if input == nil {
		return verify.NewVerifier()
	}
	opts := []verify.Option{
		verify.WithPinnedRegisters(input.PinnedRegisters),
		verify.WithFreshnessMaxAge(input.FreshnessMaxAge),
	}
	if input.EmbeddedConfig != nil {
		opts = append(opts, verify.WithEmbeddedReferences(verify.EmbeddedReferences{Config: input.EmbeddedConfig}))
	}
	if input.ConfigAuthorizer != nil {
		opts = append(opts, verify.WithConfigAuthorizer(input.ConfigAuthorizer))
	}
	return verify.NewVerifier(opts...)
}

// NewHandle pins a repository or registry project, org/project[@revision][@sha256:digest].
// The document's collateral version selects verification on first use.
// An embedded config permits an empty repo and authorizes only its exact bytes.
// A ConfigAuthorizer requires an empty repo and owns config authorization.
func NewHandle(enclave, repo string, opts *Options) (*Handle, error) {
	customConfig := opts != nil && (opts.EmbeddedConfig != nil || opts.ConfigAuthorizer != nil)
	if enclave == "" && customConfig {
		return nil, &ConfigurationError{Err: fmt.Errorf("caller-authorized config requires an enclave")}
	}
	if repo != "" && opts != nil && opts.ConfigAuthorizer != nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("config authorizer requires an empty repository pin")}
	}
	if repo != "" || !customConfig {
		if _, _, _, err := verify.ParseReference(repo); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	}
	verifier, err := opts.Verifier()
	if err != nil {
		return nil, fromVerify(err)
	}
	return &Handle{enclave: enclave, repo: repo, verifier: verifier}, nil
}

// NewHandleWithVerifier is NewHandle with a policy the caller built, which
// several handles can share; nil selects the defaults, which require a
// repository pin. A caller-authorized config used with a repository pin is
// reported when verifying.
func NewHandleWithVerifier(enclave, repo string, v *verify.Verifier) (*Handle, error) {
	if repo == "" && v == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("the default verification policy requires a repository pin")}
	}
	if repo != "" {
		if _, _, _, err := verify.ParseReference(repo); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	}
	if v == nil {
		var err error
		if v, err = verify.NewVerifier(); err != nil {
			return nil, fromVerify(err)
		}
	}
	return &Handle{enclave: enclave, repo: repo, verifier: v}, nil
}

// NewDefaultHandle applies opts to every discovered router and fallback.
func NewDefaultHandle(opts *Options) (*Handle, error) {
	if opts != nil && (opts.EmbeddedConfig != nil || opts.ConfigAuthorizer != nil) {
		return nil, &ConfigurationError{Err: fmt.Errorf("caller-authorized config requires an explicit enclave")}
	}
	verifier, err := opts.Verifier()
	if err != nil {
		return nil, fromVerify(err)
	}
	return DiscoverRouter(context.Background(), verifier)
}

// DiscoverRouter returns a handle for the first router from Tinfoil's router
// list that verifies under v, and otherwise for inference.tinfoil.sh, which it
// leaves to be verified on first use. nil v selects the default policy.
func DiscoverRouter(ctx context.Context, v *verify.Verifier) (*Handle, error) {
	fallback, err := NewHandleWithVerifier("inference.tinfoil.sh", defaultRouterRepo, v)
	if err != nil {
		return nil, err
	}
	routers, _ := fetchRouters(ctx)
	for _, routerURL := range routers {
		client := fallback.ForEnclave(routerURL)
		_, err := client.verifiedState(ctx, true, candidateVerificationRetries)
		if err == nil {
			return client, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return fallback, nil
}

// ForEnclave keeps the repository reference and verification options.
func (s *Handle) ForEnclave(enclave string) *Handle {
	return &Handle{enclave: enclave, repo: s.repo, verifier: s.verifier}
}

// ViaRelay fetches attestation through relay, which forwards it to the enclave.
func (s *Handle) ViaRelay(relay string) *Handle {
	return &Handle{enclave: s.enclave, repo: s.repo, relay: relay, verifier: s.verifier}
}

// Enclave returns the enclave URL
func (s *Handle) Enclave() string {
	return s.enclave
}

// Repo returns the trusted repository or registry reference, including version and digest pins.
func (s *Handle) Repo() string {
	return s.repo
}

// Verification returns a copy of the last verification, or nil before the first.
func (s *Handle) Verification() *verify.Verification {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if s.state == nil {
		return nil
	}
	return detached(s.state.Verification)
}

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave
func (s *Handle) HTTPClient() (*http.Client, error) {
	s.stateMu.Lock()
	if s.tlsTransport == nil {
		s.tlsTransport = &clientTransport{client: s, binding: TLS}
	}
	transport := s.tlsTransport
	s.stateMu.Unlock()
	if err := s.registerTransport(transport); err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport}, nil
}
