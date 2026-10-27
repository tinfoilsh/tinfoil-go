package tinfoil

import (
	"context"

	"github.com/tinfoilsh/tinfoil-go/internal/gateway"
)

type CatalogEntry = gateway.CatalogEntry

// Catalog maps model names to untrusted repository and replica entries.
type Catalog = gateway.Catalog

// FetchCatalog reads the catalog of the gateway at host, keeping only models
// with replicas of a bare tinfoilsh/ repository, without a tag or digest.
func FetchCatalog(ctx context.Context, host string) (Catalog, error) {
	return gateway.FetchCatalog(ctx, host)
}
