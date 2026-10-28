// Package router discovers Tinfoil's router, the default route until the
// gateway replaces it.
package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
)

const (
	routerFetchTimeout = 30 * time.Second
	// discoveryTimeout bounds the router list fetch and every probe together,
	// so a long list of unreachable routers can't hold up a client before it
	// falls back.
	discoveryTimeout = 30 * time.Second
	maxRouterBytes   = 32 << 20
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
	// Copy http.DefaultClient so an application's process-wide settings still
	// apply, while refusing a redirect that would fetch the list in plaintext.
	client := *http.DefaultClient
	client.CheckRedirect = fetch.RefuseInsecureRedirects
	resp, err := client.Do(req)
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

// Discover returns a handle for the first router from Tinfoil's router
// list that verifies under v and passes check, and otherwise for
// inference.tinfoil.sh, which it leaves to be verified on first use. nil v
// selects the default policy, and nil check accepts every router. It stops
// trying routers after discoveryTimeout, or sooner when ctx ends.
func Discover(ctx context.Context, v *verify.Verifier, check func(v *verify.Verification) error) (*enclave.Handle, error) {
	fallback, err := enclave.NewHandle(enclave.Config{Host: "inference.tinfoil.sh", Repo: defaultRouterRepo, Verifier: v, VerificationCheck: check})
	if err != nil {
		return nil, err
	}
	// Once probing expires, VerifyOnce fails each remaining router at once,
	// without a fetch.
	probing, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	deadline, _ := probing.Deadline()
	routers, _ := fetchRouters(probing)
	for _, router := range routers {
		// The deadline can pass before probing's timer cancels it, as when a
		// probe's own timeout ends at the same instant.
		if !time.Now().Before(deadline) {
			break
		}
		candidate, err := enclave.NewHandle(enclave.Config{Host: router, Repo: fallback.Repo(), Verifier: fallback.Verifier(), VerificationCheck: check})
		if err != nil {
			return nil, err
		}
		if _, err := candidate.VerifyOnce(probing); err == nil {
			return candidate, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return fallback, nil
}
