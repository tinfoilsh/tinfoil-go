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
	"time"

	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/sdkinfo"
)

// SDK identifies the SDK making a request, in the Tinfoil-SDK and
// Tinfoil-SDK-Version headers. The zero value identifies this module.
type SDK struct{ Name, Version string }

// Document retrieves a v3 attestation document from an enclave host using a
// fresh challenge nonce, returning the raw response bytes for verification. If
// relay is an empty string, the document is fetched from the host URL.
// Otherwise, the request is made to the relay URL. The fetch stops when ctx is
// done or after 30 seconds, whichever comes first.
func Document(ctx context.Context, host, relay string, nonce []byte, sdk SDK) (result []byte, err error) {
	defer func() { err = errs.WrapFetch(err) }()
	target, err := URL(host, relay, nonce)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, attestationFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	if sdk.Name == "" {
		sdk = SDK{Name: sdkinfo.Name, Version: sdkinfo.Version()}
	}
	req.Header.Set(sdkNameHeader, sdk.Name)
	req.Header.Set(sdkVersionHeader, sdk.Version)
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
	// Replacing CheckRedirect drops the default 10-redirect limit, so restate it.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-HTTPS URL %s", req.URL.Redacted())
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP GET %s: %d %s", target, resp.StatusCode, resp.Status)
	}
	// LimitReader truncates silently. Reading one byte past the limit tells an
	// oversized document apart from one of exactly the maximum size.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAttestationBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxAttestationBytes {
		return nil, fmt.Errorf("attestation document exceeds %d bytes", maxAttestationBytes)
	}
	return body, nil
}

// URL returns where the attestation document of host is fetched with nonce:
// from host itself, or from relay, which forwards the request to host, when
// relay is not empty. Both are a host with an optional port, not a URL.
func URL(host, relay string, nonce []byte) (string, error) {
	if host == "" {
		return "", &errs.ConfigurationError{Err: fmt.Errorf("enclave host is required")}
	}
	if len(nonce) != document.NonceSize {
		return "", &errs.ConfigurationError{Err: fmt.Errorf("nonce must be %d bytes, got %d", document.NonceSize, len(nonce))}
	}
	for _, authority := range []string{host, relay} {
		if authority != "" && !isAuthority(authority) {
			return "", &errs.ConfigurationError{Err: fmt.Errorf("invalid host %q: want a host with an optional port", authority)}
		}
	}
	u := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     attestationEndpoint,
		RawQuery: "nonce=" + hex.EncodeToString(nonce),
	}
	if relay != "" {
		u.Host = relay
		u.RawQuery += "&enclave=" + url.QueryEscape(host)
	}
	return u.String(), nil
}

// isAuthority reports whether s parses back as exactly the host of an HTTPS
// URL, which rejects a URL, a path or user information passed as a host.
func isAuthority(s string) bool {
	parsed, err := url.Parse((&url.URL{Scheme: "https", Host: s}).String())
	return err == nil && parsed.Host == s && parsed.Path == "" && parsed.User == nil
}

const (
	attestationEndpoint     = "/.well-known/tinfoil-attestation"
	sdkNameHeader           = "Tinfoil-SDK"
	sdkVersionHeader        = "Tinfoil-SDK-Version"
	attestationFetchTimeout = 30 * time.Second
	maxAttestationBytes     = 32 << 20
)
