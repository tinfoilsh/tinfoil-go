package tinfoil

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verifier"
)

const (
	catalogPath         = "/catalog"
	catalogFetchTimeout = 10 * time.Second
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
		return nil, &FetchError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &FetchError{Err: fmt.Errorf("fetching gateway catalog: %s", resp.Status)}
	}
	var catalog Catalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, &FetchError{Err: fmt.Errorf("decoding gateway catalog: %w", err)}
	}
	maps.DeleteFunc(catalog, func(_ string, entry CatalogEntry) bool { return !entry.trusted() })
	return catalog, nil
}

func (e CatalogEntry) trusted() bool {
	repo, _, _, err := verifier.ParseReference(e.Repo)
	return err == nil && repo == e.Repo && strings.HasPrefix(repo, trustedRepoOwner) && len(e.Hosts) > 0
}
