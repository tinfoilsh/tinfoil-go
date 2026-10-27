package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const (
	catalogPath         = "/catalog"
	catalogFetchTimeout = 10 * time.Second
	maxCatalogBytes     = 2 << 20
	trustedRepoOwner    = "tinfoilsh/"
)

type CatalogEntry struct {
	Repo  string   `json:"repo"`
	Hosts []string `json:"hosts"`
}

// Catalog maps model names to untrusted repository and replica entries.
type Catalog map[string]CatalogEntry

// FetchCatalog reads the catalog of the gateway at host, keeping only models
// with replicas of a bare tinfoilsh/ repository, without a tag or digest.
func FetchCatalog(host string) (Catalog, error) {
	return fetchCatalog(context.Background(), host)
}

func fetchCatalog(ctx context.Context, host string) (Catalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+catalogPath, nil)
	if err != nil {
		return nil, &errs.ConfigurationError{Err: err}
	}
	resp, err := (&http.Client{Timeout: catalogFetchTimeout}).Do(req)
	if err != nil {
		return nil, &errs.NetworkError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &errs.NetworkError{Err: fmt.Errorf("fetching gateway catalog: %s", resp.Status)}
	}
	return readCatalog(resp.Body)
}

// readCatalog decodes at most maxCatalogBytes of an untrusted gateway's
// catalog, so an oversized one can't exhaust memory.
func readCatalog(r io.Reader) (Catalog, error) {
	// LimitReader truncates silently. Reading one byte past the limit tells an
	// oversized catalog apart from one of exactly the maximum size.
	body, err := io.ReadAll(io.LimitReader(r, maxCatalogBytes+1))
	if err != nil {
		return nil, &errs.NetworkError{Err: fmt.Errorf("reading gateway catalog: %w", err)}
	}
	if len(body) > maxCatalogBytes {
		return nil, &errs.NetworkError{Err: fmt.Errorf("gateway catalog exceeds %d bytes", maxCatalogBytes)}
	}
	var catalog Catalog
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&catalog); err != nil {
		return nil, &errs.NetworkError{Err: fmt.Errorf("decoding gateway catalog: %w", err)}
	}
	maps.DeleteFunc(catalog, func(_ string, entry CatalogEntry) bool { return !entry.trusted() })
	return catalog, nil
}

func (e CatalogEntry) trusted() bool {
	repo, _, _, err := verify.ParseReference(e.Repo)
	return err == nil && repo == e.Repo && strings.HasPrefix(repo, trustedRepoOwner) && len(e.Hosts) > 0
}

// lazyCatalog fetches the catalog on first use and keeps it. Concurrent
// callers share one fetch, and a failed fetch is retried on the next use.
type lazyCatalog struct {
	fetch func(context.Context) (Catalog, error)

	mu      sync.Mutex
	catalog Catalog
	loaded  bool
	call    *catalogCall
}

type catalogCall struct {
	done    chan struct{}
	catalog Catalog
	err     error
}

func (l *lazyCatalog) get(ctx context.Context) (Catalog, error) {
	l.mu.Lock()
	if l.loaded {
		defer l.mu.Unlock()
		return l.catalog, nil
	}
	call := l.call
	if call == nil {
		call = &catalogCall{done: make(chan struct{})}
		l.call = call
		go l.load(call)
	}
	l.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		return call.catalog, call.err
	}
}

func (l *lazyCatalog) load(call *catalogCall) {
	// One fetch serves every waiter, so no single caller's context applies;
	// the fetch has its own timeout.
	call.catalog, call.err = l.fetch(context.Background())
	l.mu.Lock()
	if call.err == nil {
		l.catalog, l.loaded = call.catalog, true
	}
	l.call = nil
	l.mu.Unlock()
	close(call.done)
}
