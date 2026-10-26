package tinfoil

import "github.com/tinfoilsh/tinfoil-go/internal/transport"

type CatalogEntry = transport.CatalogEntry

// Catalog maps model names to untrusted repository and replica entries.
type Catalog = transport.Catalog

// FetchCatalog reads the catalog of the gateway at host, keeping only models
// with replicas of a bare tinfoilsh/ repository, without a tag or digest.
func FetchCatalog(host string) (Catalog, error) {
	return transport.FetchCatalog(host)
}
