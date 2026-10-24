package tinfoil

import (
	"fmt"
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/enclave"
)

// enclaveURLHeader tells a proxy which enclave to forward an encrypted request
// to, so the request reaches the same enclave the client verified.
const enclaveURLHeader = "X-Tinfoil-Enclave-Url"

// TransportMode selects how the SDK secures traffic to the enclave.
type TransportMode string

const (
	// TransportEHBP encrypts request bodies end-to-end with HPKE via the
	// Encrypted HTTP Body Protocol. Only the verified enclave can decrypt them,
	// so it works through proxies. This is the default.
	TransportEHBP TransportMode = "ehbp"

	// TransportTLS pins the enclave's TLS certificate. All traffic is encrypted
	// and terminated at the verified enclave, which requires a direct
	// connection (requests through a proxy will fail).
	TransportTLS TransportMode = "tls"
)

func secureHTTPClient(handle *enclave.Handle, mode TransportMode, baseURL, userCacheSecret string) (*http.Client, error) {
	var httpClient *http.Client
	if mode == TransportTLS {
		var err error
		if httpClient, err = handle.HTTPClient(); err != nil {
			return nil, err
		}
		if err := validateTLSBaseURL(baseURL, handle.Enclave()); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	} else {
		transport, err := enclave.NewTransport(handle, enclave.EHBP)
		if err != nil {
			return nil, err
		}
		httpClient = &http.Client{Transport: withEnclaveURL(transport, handle.Enclave(), baseURL)}
	}
	httpClient.Transport = &recoveryTransport{transport: httpClient.Transport}
	return boundHTTPClient(httpClient, handle.Enclave(), baseURL, userCacheSecret)
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
	proxyOrigin, err := originOf(baseURL)
	if err != nil {
		return "", false
	}
	enclaveOrigin, err := originOf(enclaveURL)
	if err != nil {
		return "", false
	}
	if proxyOrigin == enclaveOrigin {
		return "", false
	}
	return enclaveURL, true
}

func validateTLSBaseURL(baseURL, enclave string) error {
	if baseURL == "" {
		return nil
	}

	baseOrigin, err := originOf(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}
	enclaveOrigin, err := originOf("https://" + enclave)
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
