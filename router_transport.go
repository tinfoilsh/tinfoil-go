package tinfoil

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

type enclaveClient struct {
	secure    *client.SecureClient
	transport http.RoundTripper
}

// routerTransport selects fixed clients without changing their enclave state.
type routerTransport struct {
	mu        sync.Mutex
	selected  *enclaveClient
	selectNew func() (*enclaveClient, error)
	selecting *routerSelection
	origins   map[string]struct{}
	proxy     string
}

type routerSelection struct {
	done   chan struct{}
	client *enclaveClient
	err    error
}

func (t *routerTransport) current() *enclaveClient {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.selected
}

func (t *routerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	selected := t.current()
	origin := normalizedOrigin(req.URL)
	enclaveOrigin, _ := originOf("https://" + selected.secure.Enclave())
	if _, allowed := t.origins[origin]; !allowed && origin != enclaveOrigin {
		closeRequestBody(req)
		return nil, &ConfigurationError{Err: fmt.Errorf("refusing to send request to %q: client is bound to enclave %q", origin, selected.secure.Enclave())}
	}
	recovery := &recoveryTransport{transport: &enclaveDestination{client: selected, proxy: t.proxy}}
	if t.selectNew != nil {
		recovery.recover = func(ctx context.Context) (http.RoundTripper, error) {
			next, err := t.reselect(ctx, selected)
			if err != nil {
				return nil, err
			}
			return &enclaveDestination{client: next, proxy: t.proxy}, nil
		}
	}
	return recovery.RoundTrip(req)
}

type enclaveDestination struct {
	client *enclaveClient
	proxy  string
}

func (t *enclaveDestination) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if t.proxy == "" || normalizedOrigin(req.URL) != t.proxy {
		req.URL.Scheme, req.URL.Host = "https", t.client.secure.Enclave()
	}
	req.Host = req.URL.Host
	req.Header.Set(sealHeader, t.client.secure.Enclave())
	return t.client.transport.RoundTrip(req)
}

func (t *routerTransport) reselect(ctx context.Context, observed *enclaveClient) (*enclaveClient, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	if t.selected != observed {
		next := t.selected
		t.mu.Unlock()
		return next, nil
	}
	call := t.selecting
	if call == nil {
		call = &routerSelection{done: make(chan struct{})}
		t.selecting = call
		go func() {
			next, err := t.selectNew()
			t.mu.Lock()
			if err == nil {
				t.selected = next
			}
			call.client, call.err = next, err
			t.selecting = nil
			close(call.done)
			t.mu.Unlock()
		}()
	}
	t.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		return call.client, call.err
	}
}

func (t *routerTransport) CloseIdleConnections() {
	if closer, ok := t.current().transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
