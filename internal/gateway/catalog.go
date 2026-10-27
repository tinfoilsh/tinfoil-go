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

	"golang.org/x/sync/singleflight"

	"github.com/tinfoilsh/tinfoil-go/internal/errs"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const (
	catalogPath         = "/catalog"
	catalogFetchTimeout = 10 * time.Second
	// The gateway lists only replicas passing its health checks and reloads
	// its config every 10 seconds, so a client refreshes as often.
	catalogRefreshInterval = 10 * time.Second
	maxCatalogBytes        = 2 << 20
	trustedRepoOwner       = "tinfoilsh/"
)

type CatalogEntry struct {
	Repo  string   `json:"repo"`
	Hosts []string `json:"hosts"`
}

// Catalog maps model names to untrusted repository and replica entries.
type Catalog map[string]CatalogEntry

// FetchCatalog reads the catalog of the gateway at host, keeping only models
// with replicas of a bare tinfoilsh/ repository, without a tag or digest.
func FetchCatalog(ctx context.Context, host string) (Catalog, error) {
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

// catalogCache fetches the catalog on first use and refreshes it on use once
// catalogRefreshInterval has passed. Concurrent callers share one fetch. Until
// a fetch succeeds, callers wait for it and a failure is retried on the next
// use. After that, callers never wait: a stale catalog is returned while a
// refresh runs, and a failed refresh keeps it for another interval.
type catalogCache struct {
	fetch func(context.Context) (Catalog, error)
	group singleflight.Group

	// mu is held from a caller's check through its DoChan, so a fetch that
	// finishes after the check can't be followed by a redundant one.
	mu        sync.Mutex
	catalog   Catalog
	loaded    bool
	refreshAt time.Time
}

func (c *catalogCache) get(ctx context.Context) (Catalog, error) {
	c.mu.Lock()
	if c.loaded {
		defer c.mu.Unlock()
		if !time.Now().Before(c.refreshAt) {
			c.group.DoChan("", c.load)
		}
		return c.catalog, nil
	}
	fetched := c.group.DoChan("", c.load)
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-fetched:
		if result.Err != nil {
			return nil, result.Err
		}
		return result.Val.(Catalog), nil
	}
}

func (c *catalogCache) load() (any, error) {
	// One fetch serves every waiter, so no single caller's context applies;
	// the fetch has its own timeout.
	catalog, err := c.fetch(context.Background())
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.catalog, c.loaded = catalog, true
	}
	if c.loaded {
		c.refreshAt = time.Now().Add(catalogRefreshInterval)
	}
	return catalog, err
}
