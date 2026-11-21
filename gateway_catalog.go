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
//
// A failure to fetch or read the catalog is an ErrNetwork error, including
// when the fetch reaches its own limit of 10 seconds, except that the caller's
// cancellation is returned unchanged: when ctx is done, the error is
// ctx.Err() itself, which matches no category. A host that doesn't form a
// valid URL is an ErrConfiguration error, even when ctx is done.
func FetchCatalog(ctx context.Context, host string) (Catalog, error) {
	return gateway.FetchCatalog(ctx, host)
}
