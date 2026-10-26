package tinfoil

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
)

// secureHTTPClient returns the client a route sends through and the enclave
// transport inside it, which verifies on demand. It does no network I/O.
func secureHTTPClient(handle *enclave.Handle, binding enclave.Binding, baseURL, userCacheSecret string) (*http.Client, *transport.EnclaveTransport, error) {
	if binding == enclave.TLS {
		if err := transport.ValidateTLSBaseURL(baseURL, handle.Enclave()); err != nil {
			return nil, nil, &ConfigurationError{Err: err}
		}
	}
	bound, err := transport.Enclave(handle, binding, baseURL)
	if err != nil {
		return nil, nil, err
	}
	secure, err := transport.BoundHTTPClient(&http.Client{Transport: bound}, handle.Enclave(), baseURL, userCacheSecret)
	if err != nil {
		return nil, nil, err
	}
	return secure, bound, nil
}

// validateBaseURL requires an absolute HTTPS URL, which keeps request headers
// private on the way to the enclave or proxy.
func validateBaseURL(baseURL string) error {
	origin, err := transport.OriginOf(baseURL)
	if err != nil {
		return &ConfigurationError{Err: fmt.Errorf("invalid base URL: %w", err)}
	}
	if !strings.HasPrefix(origin, "https://") {
		return &ConfigurationError{Err: fmt.Errorf("invalid base URL: HTTPS is required to protect request headers")}
	}
	return nil
}
