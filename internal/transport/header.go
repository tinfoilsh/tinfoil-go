package transport

import "net/http"

// enclaveURLHeader tells a proxy which enclave to forward an encrypted request
// to, so the request reaches the same enclave the client verified.
const enclaveURLHeader = "X-Tinfoil-Enclave-Url"

// WithEnclaveURL adds the X-Tinfoil-Enclave-Url header when baseURL is a proxy
// on another origin than the enclave, and otherwise returns next.
func WithEnclaveURL(next http.RoundTripper, enclave, baseURL string) http.RoundTripper {
	headerValue, proxied := enclaveURLHeaderValue(baseURL, enclave)
	if !proxied {
		return next
	}
	return &enclaveURLHeaderTransport{enclaveURL: headerValue, transport: next}
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

// enclaveURLHeaderTransport injects the X-Tinfoil-Enclave-Url header before
// delegating to the wrapped transport. EHBP leaves request headers in
// plaintext, so the header reaches the proxy while the body stays sealed to the
// enclave's HPKE key. The value is the verified enclave's host, which never
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
