package tinfoil

import (
	"fmt"
	"net/http"

	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/client"
	"github.com/tinfoilsh/tinfoil-go/verify"
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

func secureHTTPClient(secureClient *client.SecureClient, mode TransportMode, baseURL, userCacheSecret string) (*http.Client, error) {
	var httpClient *http.Client
	if mode == TransportTLS {
		var err error
		if httpClient, err = secureClient.HTTPClient(); err != nil {
			return nil, err
		}
		if err := validateTLSBaseURL(baseURL, secureClient.Enclave()); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	} else {
		var err error
		if httpClient, err = ehbpHTTPClient(secureClient, secureClient.Enclave(), baseURL); err != nil {
			return nil, err
		}
	}
	httpClient.Transport = &recoveryTransport{transport: httpClient.Transport}
	return boundHTTPClient(httpClient, secureClient.Enclave(), baseURL, userCacheSecret)
}

type transportVerifier interface {
	NewTransport(func(*verify.Verification) (http.RoundTripper, error), func(error) bool) (http.RoundTripper, error)
}

func ehbpHTTPClient(secureClient transportVerifier, enclave, baseURL string) (*http.Client, error) {
	headerValue, proxied := enclaveURLHeaderValue(baseURL, enclave)
	transport, err := secureClient.NewTransport(func(verified *verify.Verification) (http.RoundTripper, error) {
		key, err := verified.HPKEPublicKey()
		if err != nil {
			return nil, fmt.Errorf("%w; cannot use the EHBP transport (use WithTransport(TransportTLS))", err)
		}
		inner, err := buildEHBPTransport(key)
		if err != nil {
			return nil, &AttestationError{Err: err}
		}
		if proxied {
			return &enclaveURLHeaderTransport{enclaveURL: headerValue, transport: inner}, nil
		}
		return inner, nil
	}, ehbpidentity.IsKeyConfigError)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport}, nil
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
// enclave's HPKE key. The value is the SecureClient's enclave, which never
// changes, so every transport rebuilt after re-verification and every retry
// points at the enclave that was verified.
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

func buildEHBPTransport(hpkePublicKeyHex string) (http.RoundTripper, error) {
	serverIdentity, err := ehbpidentity.FromPublicKeyHex(hpkePublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HPKE public key: %w", err)
	}

	transport, err := ehbpclient.NewTransportWithIdentity(serverIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to create EHBP transport: %w", err)
	}
	return transport, nil
}
