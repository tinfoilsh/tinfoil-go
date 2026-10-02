package tinfoil

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func boundHTTPClient(httpClient *http.Client, enclave, baseURL, userCacheSecret string) (*http.Client, error) {
	// The cache-secret layer sits above the sealing transport, so the field it
	// injects is encrypted with the rest of the body (EHBP) or sent over the
	// pinned connection (TLS).
	transport := httpClient.Transport
	if userCacheSecret != "" {
		transport = &userCacheSecretTransport{
			secret:    userCacheSecret,
			transport: transport,
		}
	}

	origins, err := allowedOrigins(enclave, baseURL)
	if err != nil {
		return nil, &ConfigurationError{Err: fmt.Errorf("failed to determine allowed request origins: %w", err)}
	}
	httpClient.Transport = &hostBoundRoundTripper{
		allowedOrigins: origins,
		enclave:        enclave,
		transport:      transport,
	}
	return httpClient, nil
}

func allowedOrigins(enclave, baseURL string) (map[string]struct{}, error) {
	origins := make(map[string]struct{}, 2)
	if enclave != "" {
		origin, err := originOf("https://" + enclave)
		if err != nil {
			return nil, err
		}
		origins[origin] = struct{}{}
	}
	if baseURL != "" {
		origin, err := originOf(baseURL)
		if err != nil {
			return nil, err
		}
		origins[origin] = struct{}{}
	}
	return origins, nil
}

// hostBoundRoundTripper rejects requests to any origin other than the verified
// enclave or the configured proxy. This guards the escape-hatch HTTP client
// (and the OpenAI client) from disclosing sensitive request headers, such as the
// API key, to an arbitrary host.
type hostBoundRoundTripper struct {
	allowedOrigins map[string]struct{}
	enclave        string
	transport      http.RoundTripper
}

func (t *hostBoundRoundTripper) CloseIdleConnections() {
	closeIdleConnections(t.transport)
}

func (t *hostBoundRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	origin := normalizedOrigin(req.URL)
	if _, ok := t.allowedOrigins[origin]; !ok {
		return nil, &ConfigurationError{Err: fmt.Errorf("refusing to send request to %q: client is bound to enclave %q", origin, t.enclave)}
	}
	return t.transport.RoundTrip(req)
}

func originOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("URL must be absolute: %q", rawURL)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("URL must use http or https: %q", rawURL)
	}
	return normalizedOrigin(u), nil
}

// normalizedOrigin lowercases the scheme and host and drops an explicit
// default port so that origins compare equal regardless of how the URL spells
// them (for example https://host and https://host:443).
func normalizedOrigin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(hostname, port)
	}
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	return scheme + "://" + hostname
}
