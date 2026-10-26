// Package enclave connects to attested enclaves. A Handle fetches and verifies
// one enclave's attestation and keeps the result until it expires or is
// invalidated; a Transport binds HTTP traffic to the keys it endorses.
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
)

// Handle is the client-side handle for one attested enclave. It verifies the
// enclave's attestation on first use, and again when the result expires or is
// invalidated. Transports built on it bind traffic to the keys of the State it
// ensures is valid; they all share one verification and one refresh.
type Handle struct {
	enclave, repo, relay string
	// verifier is the immutable verification policy, shareable across handles.
	verifier *verify.Verifier

	stateMu    sync.RWMutex
	state      *State
	generation uint64
	refreshing *verificationCall
	verify     func() (*verify.Verification, error)
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

// Config describes the enclave a Handle verifies.
type Config struct {
	// Host is the enclave, a host with an optional port.
	Host string
	// Relay, when set, is a host that fetches attestation from the enclave on
	// the client's behalf.
	Relay string
	// Repo pins a repository or registry project,
	// org/project[@revision][@sha256:digest].
	Repo string
	// Verifier is the policy, which several handles can share; nil selects the
	// defaults, which require Repo.
	Verifier *verify.Verifier
}

// NewHandle checks c and does no network I/O; the enclave is verified on
// first use. A caller-authorized config used with a repository pin is
// reported when verifying.
func NewHandle(c Config) (*Handle, error) {
	if c.Repo == "" && c.Verifier == nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("the default verification policy requires a repository pin")}
	}
	if c.Repo != "" {
		if _, _, _, err := verify.ParseReference(c.Repo); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	}
	v := c.Verifier
	if v == nil {
		var err error
		if v, err = verify.NewVerifier(); err != nil {
			return nil, fromVerify(err)
		}
	}
	return &Handle{enclave: c.Host, repo: c.Repo, relay: c.Relay, verifier: v}, nil
}

// DiscoverRouter returns a handle for the first router from Tinfoil's router
// list that verifies under v, and otherwise for inference.tinfoil.sh, which it
// leaves to be verified on first use. nil v selects the default policy.
func DiscoverRouter(ctx context.Context, v *verify.Verifier) (*Handle, error) {
	fallback, err := NewHandle(Config{Host: "inference.tinfoil.sh", Repo: defaultRouterRepo, Verifier: v})
	if err != nil {
		return nil, err
	}
	routers, _ := fetchRouters(ctx)
	for _, router := range routers {
		candidate := &Handle{enclave: router, repo: fallback.repo, verifier: fallback.verifier}
		if _, err := candidate.verifiedState(ctx, true, candidateVerificationRetries); err == nil {
			return candidate, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return fallback, nil
}

// Enclave returns the enclave host.
func (s *Handle) Enclave() string {
	return s.enclave
}

// Repo returns the trusted repository or registry reference, including version and digest pins.
func (s *Handle) Repo() string {
	return s.repo
}

// Current returns the last successful verification without checking it, or
// nil before the first. It may have expired or been invalidated; use
// EnsureVerified for one that is valid.
func (s *Handle) Current() *State {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}
