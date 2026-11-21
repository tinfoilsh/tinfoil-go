// Package fetch retrieves raw attestation documents from enclaves. It parses
// nothing; verification belongs to the verify package.
package fetch

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

// Func obtains the raw attestation document of host for nonce. The verifier
// treats whatever it returns as untrusted.
type Func func(ctx context.Context, host string, nonce []byte) ([]byte, error)

// Document retrieves a v3 attestation document directly from an enclave host
// using a fresh challenge nonce, returning the raw response bytes for
// verification. The fetch stops when ctx is done or after 30 seconds,
// whichever comes first; see Get for how it reports each.
func Document(ctx context.Context, host string, nonce []byte) ([]byte, error) {
	target, err := URL(host, "", nonce)
	if err != nil {
		return nil, errs.Configuration(err)
	}
	return Get(ctx, target, maxAttestationBytes, "attestation document")
}

// Relayed retrieves the attestation document of host through the relay at
// relayURL, as RelayURL describes, under the same bounds as Document.
func Relayed(ctx context.Context, relayURL, host string, nonce []byte) ([]byte, error) {
	target, err := RelayURL(relayURL, host, nonce)
	if err != nil {
		return nil, errs.Configuration(err)
	}
	return Get(ctx, target, maxAttestationBytes, "attestation document")
}

// Get fetches target with the SDK's identity headers and returns at most
// limit bytes of a successful response; what describes the response in
// errors. It refuses a redirect to a non-HTTPS URL, stops when ctx is done or
// after 30 seconds, whichever comes first, and reports failures as network
// errors, except that a request or read that stops because ctx ended returns
// its error with no category, matching ctx.Err() with errors.Is. A failure
// that came first, or its own 30-second limit, is a network error.
func Get(ctx context.Context, target string, limit int, what string) ([]byte, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, attestationFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, target, nil)
	if err != nil {
		return nil, errs.Configuration(err)
	}
	req.Header.Set(sdkNameHeader, sdkinfo.Name)
	req.Header.Set(sdkVersionHeader, sdkinfo.Version())
	// Copy http.DefaultClient so an application's process-wide settings (its
	// transport, proxy or timeout) still apply, while the CheckRedirect below
	// leaves the shared client untouched.
	client := *http.DefaultClient
	// A nil Transport means http.DefaultTransport; resolve it so it can be
	// cloned below.
	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}
	// Use a private connection pool. A pooled connection, possibly opened by
	// other traffic on the shared transport, may still reach a draining replica
	// after a cutover. A transport that is not an *http.Transport cannot be
	// cloned and keeps its own pooling.
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport = transport.Clone()
		defer transport.CloseIdleConnections()
		client.Transport = transport
	}
	client.CheckRedirect = RefuseInsecureRedirects
	resp, err := client.Do(req)
	if err != nil {
		return nil, errs.Interrupted(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, errs.Network(fmt.Errorf("HTTP GET %s: %d %s", target, resp.StatusCode, resp.Status))
	}
	// LimitReader truncates silently. Reading one byte past the limit tells an
	// oversized response apart from one of exactly the maximum size.
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, errs.Interrupted(ctx, err)
	}
	if len(body) > limit {
		return nil, errs.Network(fmt.Errorf("%s exceeds %d bytes", what, limit))
	}
	return body, nil
}

// RefuseInsecureRedirects is an http.Client CheckRedirect that refuses a
// redirect to a non-HTTPS URL. Replacing CheckRedirect drops the default limit
// of 10 redirects, so it restates it.
func RefuseInsecureRedirects(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-HTTPS URL %s", req.URL.Redacted())
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// URL returns where the attestation document of host is fetched with nonce:
// from host itself, or from relay, which forwards the request to host, when
// relay is not empty. Both are a host with an optional port, not a URL.
func URL(host, relay string, nonce []byte) (string, error) {
	if err := checkTarget(host, nonce); err != nil {
		return "", err
	}
	if relay == "" {
		u := url.URL{Scheme: "https", Host: host, Path: attestationEndpoint, RawQuery: "nonce=" + hex.EncodeToString(nonce)}
		return u.String(), nil
	}
	if !isAuthority(relay) {
		return "", fmt.Errorf("invalid host %q: want a host with an optional port", relay)
	}
	return RelayURL("https://"+relay, host, nonce)
}

// RelayURL returns where the attestation document of host is fetched with
// nonce through the relay at relayURL: the attestation path joined under
// relayURL's path, whether or not that ends with "/", with the nonce in
// lowercase hex and the enclave host as query parameters. relayURL must be an
// absolute http or https URL without user information, a query or a fragment;
// which schemes a caller may use is its own policy.
func RelayURL(relayURL, host string, nonce []byte) (string, error) {
	if err := checkTarget(host, nonce); err != nil {
		return "", err
	}
	u, err := ParseBaseURL(relayURL)
	if err != nil {
		return "", err
	}
	u = u.JoinPath(attestationEndpoint)
	u.RawQuery = "nonce=" + hex.EncodeToString(nonce) + "&enclave=" + url.QueryEscape(host)
	return u.String(), nil
}

// ParseBaseURL parses rawURL as a URL that request paths join under: an
// absolute http or https URL with a host and without user information, a
// query or a fragment, even an empty one.
func ParseBaseURL(rawURL string) (*url.URL, error) {
	// Errors don't echo the URL, which may carry credentials.
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("URL does not parse")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("URL must use http or https")
	}
	if u.Host == "" || u.Opaque != "" {
		return nil, errors.New("URL must be absolute, with a scheme and a host")
	}
	if u.User != nil {
		return nil, errors.New("URL must not contain user information")
	}
	// url.URL doesn't record an empty fragment; once the URL has parsed, a
	// '?' or '#' in it can only start a query or a fragment.
	if strings.ContainsAny(rawURL, "?#") {
		return nil, errors.New("URL must not carry a query or a fragment")
	}
	return u, nil
}

// CheckTarget checks the enclave host and the nonce of an attestation fetch,
// whoever performs it.
func CheckTarget(host string, nonce []byte) error {
	return checkTarget(host, nonce)
}

// checkTarget checks the enclave host and the nonce of an attestation fetch.
func checkTarget(host string, nonce []byte) error {
	if host == "" {
		return fmt.Errorf("enclave host is required")
	}
	if len(nonce) != document.NonceSize {
		return fmt.Errorf("nonce must be %d bytes, got %d", document.NonceSize, len(nonce))
	}
	if !isAuthority(host) {
		return fmt.Errorf("invalid host %q: want a host with an optional port", host)
	}
	return nil
}

// isAuthority reports whether s parses back as exactly the host of an HTTPS
// URL, which rejects a URL, a path or user information passed as a host.
func isAuthority(s string) bool {
	parsed, err := url.Parse((&url.URL{Scheme: "https", Host: s}).String())
	return err == nil && parsed.Host == s && parsed.Path == "" && parsed.User == nil
}

// Timeout bounds one attestation fetch, whoever performs it.
const Timeout = attestationFetchTimeout

const (
	attestationEndpoint     = "/.well-known/tinfoil-attestation"
	sdkNameHeader           = "Tinfoil-SDK"
	sdkVersionHeader        = "Tinfoil-SDK-Version"
	attestationFetchTimeout = 30 * time.Second
	maxAttestationBytes     = 32 << 20
)
