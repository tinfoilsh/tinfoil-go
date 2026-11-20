package tinfoil

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
)

// Transport selects how a client protects its traffic to an enclave. It is
// TLS or EHBP, passed as a value; a nil Transport selects TLS{}, the stronger
// transport. A pointer to a variant, or another type that embeds one, is an
// ErrConfiguration error.
type Transport interface {
	transport()
}

// TLS pins each connection to the attested TLS key. It protects the whole
// request and response, and needs a direct connection to the enclave, so it
// takes no URL: requests go to the enclave's own HTTPS origin. Its connections
// take only the proxy, dialer and connection-pool settings of
// http.DefaultTransport and the roots and verification callbacks of its TLS
// config; a custom TLS dialer or TLS key log there is an ErrConfiguration
// error.
type TLS struct{}

// EHBP seals request and response bodies to the attested HPKE key, so that
// they stay private through a proxy. The method, URL and headers aren't
// sealed, and neither is a request without a body or its response. It refuses
// protocol upgrades, such as WebSockets, and CONNECT tunnels, because nothing
// after the handshake would be sealed.
type EHBP struct {
	// ProxyURL, when set, is a proxy that forwards requests to the enclave,
	// and requests are sent to it; empty sends them directly to the enclave.
	// Requests to the proxy carry X-Tinfoil-Enclave-Url so that it can forward
	// them. The proxy must use HTTPS, since EHBP doesn't seal headers such as
	// the API key; http:// is accepted only when its host is localhost or a
	// loopback IP address, for a local development proxy or a sidecar.
	// Request paths join under it, so a ProxyURL with user information, a
	// query or a fragment, even an empty one, is an ErrConfiguration error.
	// An enclave client also refuses a ProxyURL on the enclave's own origin,
	// which is no proxy; leave ProxyURL empty to connect directly.
	ProxyURL string
}

func (TLS) transport()  {}
func (EHBP) transport() {}

// resolveTransport returns t, or TLS{} for nil, after checking the values
// that the variant carries.
func resolveTransport(t Transport) (Transport, error) {
	switch t := t.(type) {
	case nil:
		return TLS{}, nil
	case TLS:
		return t, nil
	case EHBP:
		if t.ProxyURL != "" {
			if err := validateProxyURL(t.ProxyURL); err != nil {
				return nil, err
			}
		}
		return t, nil
	default:
		return nil, errs.Configuration(fmt.Errorf("transport must be a TLS or EHBP value, not %T", t))
	}
}

// proxyURLOf returns the proxy that t sends requests through, or "" when it
// connects directly to the enclave.
func proxyURLOf(t Transport) string {
	if e, ok := t.(EHBP); ok {
		return e.ProxyURL
	}
	return ""
}

// keyedTransport returns the transport that verifies e and protects t's
// traffic with the keys that it verifies. t must come from resolveTransport.
func keyedTransport(t Transport, e *enclave.Enclave) *transport.Transport {
	if _, ok := t.(EHBP); ok {
		return transport.WithEHBP(nil, e)
	}
	return transport.TLS(e)
}

// validateProxyURL requires an absolute URL that keeps request headers private
// on the way to the proxy: HTTPS, or HTTP to a loopback host, whose traffic
// never leaves the machine. It refuses user information (through
// transport.OriginOf) and a query or a fragment (through
// refuseQueryOrFragment).
func validateProxyURL(proxyURL string) error {
	origin, err := transport.OriginOf(proxyURL)
	if err != nil {
		return errs.Configuration(fmt.Errorf("invalid proxy URL: %w", err))
	}
	if err := refuseQueryOrFragment("proxy URL", proxyURL); err != nil {
		return err
	}
	if strings.HasPrefix(origin, "https://") {
		return nil
	}
	u, _ := url.Parse(proxyURL) // OriginOf parsed it
	if !isLoopback(u.Hostname()) {
		return errs.Configuration(errors.New("invalid proxy URL: HTTP is allowed only for localhost or a loopback IP address; use HTTPS to protect request headers"))
	}
	return nil
}

// refuseEnclaveOriginProxy refuses a proxy URL on the enclave's own origin,
// which would send requests directly to the enclave under the name of a
// proxy.
func refuseEnclaveOriginProxy(proxyURL, enclave string) error {
	if proxyURL == "" {
		return nil
	}
	proxyOrigin, err := transport.OriginOf(proxyURL)
	if err != nil {
		return errs.Configuration(fmt.Errorf("invalid proxy URL: %w", err))
	}
	enclaveOrigin, err := transport.OriginOf("https://" + enclave)
	if err != nil {
		return errs.Configuration(fmt.Errorf("invalid enclave host: %w", err))
	}
	if proxyOrigin == enclaveOrigin {
		return errs.Configuration(fmt.Errorf("invalid proxy URL: %q is the enclave's own origin; leave ProxyURL empty to connect directly", enclaveOrigin))
	}
	return nil
}

// refuseQueryOrFragment refuses a URL, which name describes, that carries a
// query or a fragment, even an empty one: request paths join under it, so
// either would make request URLs that the caller didn't intend. It checks the
// text, since url.URL doesn't record an empty fragment; once the URL has
// parsed, a '?' or '#' in it can only start a query or a fragment.
func refuseQueryOrFragment(name, rawURL string) error {
	if strings.ContainsAny(rawURL, "?#") {
		return errs.Configuration(fmt.Errorf("invalid %s: a %s must not carry a query or a fragment", name, name))
	}
	return nil
}

// isLoopback reports whether host, as written, is localhost or a loopback IP
// address. It doesn't resolve other names, so that DNS can't make a remote
// host pass.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
