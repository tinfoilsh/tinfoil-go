package transport

import (
	"fmt"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/enclave"
)

// enclaveURLHeader tells a proxy which enclave to forward an encrypted request
// to, so the request reaches the same enclave the client verified.
const enclaveURLHeader = "X-Tinfoil-Enclave-Url"

// Enclave is the stack every route puts in front of one enclave: h's transport
// for binding b, the proxy header when baseURL is a proxy on another origin,
// and one replay after a key rejection.
func Enclave(h *enclave.Handle, b enclave.Binding, baseURL string) (http.RoundTripper, error) {
	bound, err := enclave.NewTransport(h, b)
	if err != nil {
		return nil, err
	}
	return &recoveryTransport{transport: withEnclaveURL(bound, h.Enclave(), baseURL)}, nil
}

// withEnclaveURL adds the X-Tinfoil-Enclave-Url header when baseURL is a proxy
// on another origin than the enclave.
func withEnclaveURL(transport http.RoundTripper, enclave, baseURL string) http.RoundTripper {
	headerValue, proxied := enclaveURLHeaderValue(baseURL, enclave)
	if !proxied {
		return transport
	}
	return &enclaveURLHeaderTransport{enclaveURL: headerValue, transport: transport}
}

func enclaveURLHeaderValue(baseURL, enclave string) (string, bool) {
	if baseURL == "" || enclave == "" {
		return "", false
	}
	enclaveURL := "https://" + enclave
	proxyOrigin, err := OriginOf(baseURL)
	if err != nil {
		return "", false
	}
	enclaveOrigin, err := OriginOf(enclaveURL)
	if err != nil {
		return "", false
	}
	if proxyOrigin == enclaveOrigin {
		return "", false
	}
	return enclaveURL, true
}

// ValidateTLSBaseURL requires a TLS base URL to use the enclave's own origin,
// since a pinned connection can't pass through a proxy.
func ValidateTLSBaseURL(baseURL, enclave string) error {
	if baseURL == "" {
		return nil
	}

	baseOrigin, err := OriginOf(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	enclaveOrigin, err := OriginOf("https://" + enclave)
	if err != nil {
		return err
	}
	if baseOrigin != enclaveOrigin {
		return fmt.Errorf("TLS base URL must use the verified enclave origin %q", enclaveOrigin)
	}
	return nil
}

// enclaveURLHeaderTransport injects the X-Tinfoil-Enclave-Url header before
// delegating to the wrapped transport. EHBP leaves request headers in
// plaintext, so the header reaches the proxy while the body stays sealed to the
// enclave's HPKE key. The value is the handle's enclave, which never
// changes, so every request, including retries and requests after
// re-verification, points at the enclave that was verified.
type enclaveURLHeaderTransport struct {
	enclaveURL string
	transport  http.RoundTripper
}

func (t *enclaveURLHeaderTransport) CloseIdleConnections() {
	closeIdleConnections(t.transport)
}

func (t *enclaveURLHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set(enclaveURLHeader, t.enclaveURL)
	return t.transport.RoundTrip(req)
}
