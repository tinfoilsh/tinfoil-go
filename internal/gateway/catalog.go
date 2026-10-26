package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
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
	resp, err := (&http.Client{Timeout: catalogFetchTimeout}).Get("https://" + host + catalogPath)
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
