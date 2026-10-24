package tinfoil

import (
	"net/http"

	"github.com/tinfoilsh/tinfoil-go/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
)

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
	binding := enclave.EHBP
	if mode == TransportTLS {
		binding = enclave.TLS
	}
	rt, err := transport.Enclave(handle, binding, baseURL)
	if err != nil {
		return nil, err
	}
	if mode == TransportTLS {
		if err := transport.ValidateTLSBaseURL(baseURL, handle.Enclave()); err != nil {
			return nil, &ConfigurationError{Err: err}
		}
	}
	return transport.BoundHTTPClient(&http.Client{Transport: rt}, handle.Enclave(), baseURL, userCacheSecret)
}
