package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/errs"
)

func TestReadCatalogRejectsOversizedCatalog(t *testing.T) {
	entry := `{"m":{"repo":"tinfoilsh/m","hosts":["a.example"]}}`
	maximal := entry + strings.Repeat(" ", maxCatalogBytes-len(entry))
	catalog, err := readCatalog(strings.NewReader(maximal))
	require.NoError(t, err)
	require.Contains(t, catalog, "m")

	_, err = readCatalog(strings.NewReader(maximal + " "))
	var fetch *errs.NetworkError
	require.ErrorAs(t, err, &fetch)
	require.ErrorContains(t, err, "exceeds")
}

func TestReadCatalogKeepsOnlyTrustedEntries(t *testing.T) {
	catalog, err := readCatalog(strings.NewReader(`{
		"ok": {"repo": "tinfoilsh/ok", "hosts": ["a.example"]},
		"tagged": {"repo": "tinfoilsh/ok@v1", "hosts": ["a.example"]},
		"other": {"repo": "acme/ok", "hosts": ["a.example"]},
		"empty": {"repo": "tinfoilsh/empty", "hosts": []}
	}`))
	require.NoError(t, err)
	require.Equal(t, Catalog{"ok": {Repo: "tinfoilsh/ok", Hosts: []string{"a.example"}}}, catalog)
}

func TestLazyCatalogFetchesOnFirstUseAndKeepsSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		failure := errors.New("gateway unavailable")
		release := make(chan struct{})
		var fetches int
		lazy := &lazyCatalog{fetch: func(context.Context) (Catalog, error) {
			fetches++
			<-release
			if fetches == 1 {
				return nil, failure
			}
			return Catalog{"m": {Repo: "tinfoilsh/m", Hosts: []string{"a.example"}}}, nil
		}}
		results := make(chan error, 3)
		for range cap(results) {
			go func() { _, err := lazy.get(context.Background()); results <- err }()
		}
		canceled, cancel := context.WithCancel(context.Background())
		waiter := make(chan error, 1)
		go func() { _, err := lazy.get(canceled); waiter <- err }()
		synctest.Wait()
		cancel()
		require.ErrorIs(t, <-waiter, context.Canceled, "a waiter's cancellation returns without the shared fetch")
		close(release)
		for range cap(results) {
			require.ErrorIs(t, <-results, failure)
		}
		require.Equal(t, 1, fetches, "concurrent first uses share one fetch")

		catalog, err := lazy.get(context.Background())
		require.NoError(t, err, "a failed fetch is retried on the next use")
		require.Contains(t, catalog, "m")
		_, err = lazy.get(context.Background())
		require.NoError(t, err)
		require.Equal(t, 2, fetches, "a fetched catalog is kept")
	})
}
