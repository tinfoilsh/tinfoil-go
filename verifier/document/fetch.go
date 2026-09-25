package document

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier/errs"
)

// Fetch retrieves a v3 attestation document from an enclave host using a
// fresh challenge nonce, returning the raw response bytes for verification.
// It uses http.DefaultClient with a 30-second deadline and a 32 MiB body limit,
// and follows redirects only to HTTPS URLs.
func Fetch(host string, nonce []byte) ([]byte, error) {
	return FetchVia(host, "", nonce)
}

// FetchVia is Fetch through a non-empty relay host; verification ignores the path.
func FetchVia(host, relay string, nonce []byte) (result []byte, err error) {
	defer func() { err = errs.WrapFetch(err) }()
	if host == "" {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("enclave host is required")}
	}
	if len(nonce) != NonceSize {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))}
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
	ctx, cancel := context.WithTimeout(context.Background(), attestationFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, &errs.ConfigurationError{Err: fmt.Errorf("invalid enclave host: %w", err)}
	}
	client := *http.DefaultClient
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
	attestationFetchTimeout = 30 * time.Second
	maxAttestationBytes     = 32 << 20
)
