package tinfoil

import (
	"context"
	"errors"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/fetch"
	"github.com/tinfoilsh/tinfoil-go/internal/router"
)

// AttestationFetcher obtains the attestation document of an enclave for a
// challenge nonce, in place of the client's direct fetch from the enclave.
// The client verifies whatever it returns as it verifies a document that it
// fetched itself, so a fetcher is not trusted: it can make verification fail,
// but it can't make an enclave pass that wouldn't pass otherwise.
//
// A client calls FetchAttestation for every verification: when it is created,
// whenever it verifies again after an expiry or a key rotation, and, on the
// router route, for each router that discovery tries and for the fallback.
// host is the enclave's host, with an optional port, and nonce is the fresh
// challenge that the document must answer. ctx ends after 30 seconds; it
// isn't the context of any one caller, since one verification can serve many
// requests, and each caller's cancellation ends only that caller's wait. An
// error that FetchAttestation returns is reported as an ErrNetwork error that
// wraps it, unless it already is an SDK error; that includes ctx.Err() once
// ctx ends, since the timeout is the SDK's. It may be called concurrently.
type AttestationFetcher interface {
	FetchAttestation(ctx context.Context, host string, nonce []byte) ([]byte, error)
}

// AttestationFetcherFunc is a function that serves as an AttestationFetcher.
type AttestationFetcherFunc func(ctx context.Context, host string, nonce []byte) ([]byte, error)

// FetchAttestation calls f(ctx, host, nonce).
func (f AttestationFetcherFunc) FetchAttestation(ctx context.Context, host string, nonce []byte) ([]byte, error) {
	return f(ctx, host, nonce)
}

// AttestationRelay is an AttestationFetcher that fetches documents through a
// relay, such as an endpoint on the application's own origin that forwards
// each request to the enclave that it names. A client in a browser with a
// strict content security policy, or one that shouldn't reveal its IP address
// to enclaves, then reaches only that origin.
//
// It sends GET {URL}/.well-known/tinfoil-attestation?nonce={nonce}&enclave={host},
// where nonce is the challenge in lowercase hex and host is query-escaped,
// with the SDK identity headers that a direct fetch sends, and takes the
// response body as the document. It applies the bounds of a direct fetch: 30
// seconds, 32 MiB, and no redirect to a URL that isn't HTTPS. The relay is
// not trusted; see AttestationFetcher.
type AttestationRelay struct {
	// URL is the relay's base URL. Its path, if any, is where the relay is
	// mounted: the request path joins under it, whether or not it ends with
	// "/". It must use HTTPS; http:// is accepted only when its host is
	// localhost or a loopback IP address. A URL with user information, a
	// query or a fragment, even an empty one, is an ErrConfiguration error,
	// which a client reports when it is created, before any network I/O.
	URL string
}

// FetchAttestation fetches the attestation document of host for nonce
// through the relay. A failure to fetch it is an ErrNetwork error, including
// when the fetch reaches its own limit of 30 seconds, except that the
// caller's cancellation is returned with no category: when the fetch stops
// because ctx ended, the error matches ctx.Err() with errors.Is, possibly
// wrapped, as net/http wraps it in a *url.Error. A failure that came before
// the caller cancelled keeps its category.
//
// A client that verifies through the relay reports the end of its own context
// as ErrNetwork, since that context is the SDK's, not the caller's; see
// AttestationFetcher.
func (r AttestationRelay) FetchAttestation(ctx context.Context, host string, nonce []byte) ([]byte, error) {
	if err := validateServiceURL("attestation relay URL", r.URL); err != nil {
		return nil, err
	}
	document, err := fetch.Relayed(ctx, r.URL, host, nonce)
	return document, errs.Finish(ctx, err)
}

// RouterListFetcher obtains the candidate routers for router discovery, in
// place of the client's fetch from https://atc.tinfoil.sh/routers. The list is
// not trusted: it only proposes hosts, and discovery verifies each one before
// it uses it, tries them for at most 30 seconds in all, and falls back to
// inference.tinfoil.sh when none passes. An error counts as an empty list.
//
// An attestation document doesn't name the host that serves it, so the list
// source is trusted not to name a host that would relay another router's
// attestation: with EHBP, such a host would receive the request headers,
// including the API key, although not the sealed bodies.
//
// ctx ends when the caller's context ends, or after 30 seconds.
type RouterListFetcher interface {
	FetchRouterList(ctx context.Context) ([]string, error)
}

// RouterListFetcherFunc is a function that serves as a RouterListFetcher.
type RouterListFetcherFunc func(ctx context.Context) ([]string, error)

// FetchRouterList calls f(ctx).
func (f RouterListFetcherFunc) FetchRouterList(ctx context.Context) ([]string, error) {
	return f(ctx)
}

// RouterListRelay is a RouterListFetcher that fetches the router list through
// a relay, such as an endpoint on the application's own origin that forwards
// the request to https://atc.tinfoil.sh/routers.
//
// It sends GET {URL}/routers, with the query parameters that a direct fetch
// sends, of which this client sends none, and parses the response as a
// direct fetch's: a JSON array of host strings of at most 32 MiB, fetched
// with no redirect to a URL that isn't HTTPS.
type RouterListRelay struct {
	// URL is the relay's base URL, under the rules of AttestationRelay.URL.
	URL string
}

// FetchRouterList fetches the router list through the relay. A failure to
// fetch it is an ErrNetwork error, including when the fetch reaches its own
// limit of 30 seconds, except that the
// caller's cancellation is returned with no category: when the fetch stops
// because ctx ended, the error matches ctx.Err() with errors.Is, possibly
// wrapped, as net/http wraps it in a *url.Error. A failure that came before
// the caller cancelled keeps its category.
func (r RouterListRelay) FetchRouterList(ctx context.Context) ([]string, error) {
	if err := validateServiceURL("router list relay URL", r.URL); err != nil {
		return nil, err
	}
	target, err := router.RelayListURL(r.URL)
	if err != nil {
		return nil, errs.Configuration(err)
	}
	routers, err := router.FetchList(ctx, target)
	return routers, errs.Finish(ctx, err)
}

// attestationFetchFunc returns the function that obtains documents for f, or
// nil to fetch them directly from the enclave. It checks a relay's URL, and
// copies a relay that a pointer names, so that later changes have no effect.
func attestationFetchFunc(f AttestationFetcher) (fetch.Func, error) {
	switch f := f.(type) {
	case nil:
		return nil, nil
	case AttestationFetcherFunc:
		if f == nil {
			return nil, errs.Configuration(errors.New("FetchAttestation is a nil AttestationFetcherFunc"))
		}
	case *AttestationRelay:
		if f == nil {
			return nil, errs.Configuration(errors.New("FetchAttestation is a nil *AttestationRelay"))
		}
		return attestationFetchFunc(*f)
	case AttestationRelay:
		if err := validateServiceURL("attestation relay URL", f.URL); err != nil {
			return nil, err
		}
	}
	return f.FetchAttestation, nil
}

// routerListFunc returns the function that obtains the router list for f, or
// nil to fetch Tinfoil's list. It checks and copies a relay as
// attestationFetchFunc does.
func routerListFunc(f RouterListFetcher) (router.ListFunc, error) {
	switch f := f.(type) {
	case nil:
		return nil, nil
	case RouterListFetcherFunc:
		if f == nil {
			return nil, errs.Configuration(errors.New("FetchRouterList is a nil RouterListFetcherFunc"))
		}
	case *RouterListRelay:
		if f == nil {
			return nil, errs.Configuration(errors.New("FetchRouterList is a nil *RouterListRelay"))
		}
		return routerListFunc(*f)
	case RouterListRelay:
		if err := validateServiceURL("router list relay URL", f.URL); err != nil {
			return nil, err
		}
	}
	return f.FetchRouterList, nil
}
