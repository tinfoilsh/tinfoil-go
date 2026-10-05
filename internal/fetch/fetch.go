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

// Document retrieves a v3 attestation document from an enclave host using a
// fresh challenge nonce, returning the raw response bytes for verification. If
// relay is an empty string, the document is fetched from the host URL.
// Otherwise, the request is made to the relay URL. The fetch stops when ctx is
// done or after 30 seconds, whichever comes first.
func Document(ctx context.Context, host, relay string, nonce []byte) (result []byte, err error) {
	defer func() { err = errs.WrapFetch(err) }()
	if host == "" {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("enclave host is required")}
	}
	if len(nonce) != document.NonceSize {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("nonce must be %d bytes, got %d", document.NonceSize, len(nonce))}
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
	ctx, cancel := context.WithTimeout(ctx, attestationFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("invalid enclave host: %w", err)}
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
		return nil, fmt.Errorf("HTTP GET %s: %d %s", u.String(), resp.StatusCode, resp.Status)
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

const (
	attestationEndpoint     = "/.well-known/tinfoil-attestation"
	sdkNameHeader           = "Tinfoil-SDK"
	sdkVersionHeader        = "Tinfoil-SDK-Version"
	attestationFetchTimeout = 30 * time.Second
	maxAttestationBytes     = 32 << 20
)
