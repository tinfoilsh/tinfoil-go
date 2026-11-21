// Package router discovers Tinfoil's router, the default route until the
// gateway replaces it.
package router

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"slices"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

// Name is the router's GitHub repository and config registry project.
const Name = "tinfoilsh/confidential-model-router"

var (
	// Tinfoil owns the router's name in both namespaces.
	defaultRouterPin = verify.Pin{Repo: Name, Project: Name}
	defaultRouterURL = "https://atc.tinfoil.sh/routers"
	// shuffle puts the candidates in a uniformly random order, so that
	// clients spread across routers rather than all trying the first one.
	// Tests replace it to fix the order.
	shuffle = func(routers []string) {
		rand.Shuffle(len(routers), func(i, j int) { routers[i], routers[j] = routers[j], routers[i] })
	}
)

const (
	routerFetchTimeout = 30 * time.Second
	// discoveryTimeout bounds the router list fetch and every probe together,
	// so a long list of unreachable routers can't hold up a client before it
	// falls back.
	discoveryTimeout = 30 * time.Second
	maxRouterBytes   = 32 << 20
	relayListPath    = "routers"
)

// ListFunc obtains the untrusted list of candidate routers.
type ListFunc func(ctx context.Context) ([]string, error)

// FetchList fetches the router list from listURL, as from Tinfoil's list.
// It is bounded the same way attestation fetching is: discovery runs before
// anything is verified, so an unresponsive or oversized reply must not stall
// client construction or exhaust memory. It reports failures as network
// errors, except that a request or read that stops because ctx ended returns
// its error with no category, matching ctx.Err() with errors.Is. A failure
// that came first, or its own 30-second limit, is a network error. A listURL
// that doesn't form a request is a configuration error.
func FetchList(ctx context.Context, listURL string) ([]string, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, routerFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, errs.Configuration(err)
	}
	// Copy http.DefaultClient so an application's process-wide settings still
	// apply, while refusing a redirect that would fetch the list in plaintext.
	client := *http.DefaultClient
	client.CheckRedirect = fetch.RefuseInsecureRedirects
	resp, err := client.Do(req)
	if err != nil {
		return nil, errs.Finish(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, errs.Network(fmt.Errorf("fetching routers from %s: %d %s", listURL, resp.StatusCode, resp.Status))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRouterBytes+1))
	if err != nil {
		return nil, errs.Finish(ctx, err)
	}
	if len(body) > maxRouterBytes {
		return nil, errs.Network(fmt.Errorf("router list from %s exceeds %d bytes", listURL, maxRouterBytes))
	}

	var routers []string
	if err := json.Unmarshal(body, &routers); err != nil {
		return nil, errs.Network(err)
	}

	return routers, nil
}

// RelayListURL returns where the router list is fetched through the relay at
// relayURL: "routers" joined under its path, whether or not that ends with
// "/", with the query parameters that Tinfoil's list takes, of which this
// client sends none.
func RelayListURL(relayURL string) (string, error) {
	u, err := fetch.ParseBaseURL(relayURL)
	if err != nil {
		return "", err
	}
	return u.JoinPath(relayListPath).String(), nil
}

// fetchRouters fetches Tinfoil's router list.
func fetchRouters(ctx context.Context) ([]string, error) {
	return FetchList(ctx, defaultRouterURL)
}

// Options are the inputs of Discover.
type Options struct {
	// Verifier is the policy, which must use default config trust, as the
	// router's pin requires; nil selects the default policy.
	Verifier *verify.Verifier
	// Check, when set, can reject each router's verification.
	Check func(v *verify.Verification) error
	// NewTransport makes the transport that verifies a router.
	NewTransport func(*enclave.Enclave) *transport.Transport
	// List, when set, replaces fetching Tinfoil's router list.
	List ListFunc
	// FetchAttestation, when set, replaces fetching each router's attestation
	// document from the router, for candidates and the fallback alike.
	FetchAttestation fetch.Func
}

// Discover returns the transport o.NewTransport makes for the first router
// from the router list that verifies under o.Verifier and passes o.Check, and
// otherwise for inference.tinfoil.sh, which it leaves to be verified on first
// use. A list that can't be obtained counts as empty. It stops trying routers
// after discoveryTimeout, or sooner when ctx ends.
func Discover(ctx context.Context, o Options) (*transport.Transport, error) {
	list := o.List
	if list == nil {
		list = fetchRouters
	}
	newTransport := o.NewTransport
	fallback, err := enclave.New(enclave.Config{Host: "inference.tinfoil.sh", Pin: defaultRouterPin, Verifier: o.Verifier, VerificationCheck: o.Check, FetchAttestation: o.FetchAttestation})
	if err != nil {
		return nil, err
	}
	// Once probing expires, VerifyOnce fails each remaining router at once,
	// without a fetch.
	probing, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	deadline, _ := probing.Deadline()
	// A copy, since a caller's fetcher may keep the slice that it returned.
	routers := slices.Clone(listRouters(probing, list))
	shuffle(routers)
	for _, router := range routers {
		// The deadline can pass before probing's timer cancels it, as when a
		// probe's own timeout ends at the same instant.
		if !time.Now().Before(deadline) {
			break
		}
		e, err := enclave.New(enclave.Config{Host: router, Pin: fallback.Pin(), Verifier: fallback.Verifier(), VerificationCheck: o.Check, FetchAttestation: o.FetchAttestation})
		if err != nil {
			return nil, err
		}
		// The candidate keeps the verification, so the client doesn't repeat
		// it, and a router whose keys the mode can't use is skipped.
		candidate := newTransport(e)
		if _, err := candidate.VerifyOnce(probing); err == nil {
			return candidate, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return newTransport(fallback), nil
}

// listRouters calls list with a context that ends after routerFetchTimeout,
// as a fetch of Tinfoil's list does. A list that comes with an error counts
// as empty.
func listRouters(ctx context.Context, list ListFunc) []string {
	ctx, cancel := context.WithTimeout(ctx, routerFetchTimeout)
	defer cancel()
	routers, err := list(ctx)
	if err != nil {
		return nil
	}
	return routers
}
