package tinfoil

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
)

func secureHTTPClient(handle *enclave.Handle, binding enclave.Binding, baseURL, userCacheSecret string) (*http.Client, error) {
	if binding == enclave.TLS {
		if err := transport.ValidateTLSBaseURL(baseURL, handle.Enclave()); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	}
	rt, err := transport.Enclave(handle, binding, baseURL)
	if err != nil {
		return nil, err
	}
	return transport.BoundHTTPClient(&http.Client{Transport: rt}, handle.Enclave(), baseURL, userCacheSecret)
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
