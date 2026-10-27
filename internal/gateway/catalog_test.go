package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

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

func TestCatalogCacheFetchesOnFirstUseAndKeepsSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		failure := errors.New("gateway unavailable")
		release := make(chan struct{})
		var fetches int
		lazy := &catalogCache{fetch: func(context.Context) (Catalog, error) {
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

func TestCatalogCacheRefreshesWithoutBlocking(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		catalogs := []Catalog{{"old": {Repo: "tinfoilsh/old", Hosts: []string{"a.example"}}}, nil, {"new": {Repo: "tinfoilsh/new", Hosts: []string{"b.example"}}}}
		release := make(chan struct{}, len(catalogs))
		var fetches int
		cache := &catalogCache{fetch: func(context.Context) (Catalog, error) {
			fetches++
			n := fetches
			<-release
			if catalog := catalogs[n-1]; catalog != nil {
				return catalog, nil
			}
			time.Sleep(catalogRefreshInterval) // fails slowly, as a fetch that times out does
			return nil, errors.New("gateway unavailable")
		}}
		release <- struct{}{}
		get := func() Catalog {
			catalog, err := cache.get(context.Background())
			require.NoError(t, err)
			return catalog
		}
		require.Contains(t, get(), "old")

		time.Sleep(catalogRefreshInterval - time.Nanosecond)
		require.Contains(t, get(), "old")
		synctest.Wait()
		require.Equal(t, 1, fetches, "a catalog is kept for the refresh interval")

		time.Sleep(time.Nanosecond)
		require.Contains(t, get(), "old", "a stale catalog is returned while it refreshes")
		require.True(t, time.Now().Before(cache.refreshAt), "starting a refresh moves refreshAt ahead, so later callers don't join it")
		require.Contains(t, get(), "old")
		synctest.Wait()
		require.Equal(t, 2, fetches, "a use during a refresh starts no second fetch")
		release <- struct{}{}
		time.Sleep(catalogRefreshInterval + time.Nanosecond)
		require.Contains(t, get(), "old", "a failed refresh keeps the last catalog")
		synctest.Wait()
		require.Equal(t, 2, fetches, "a failed refresh waits another interval after it finishes")

		time.Sleep(catalogRefreshInterval)
		require.Contains(t, get(), "old")
		release <- struct{}{}
		synctest.Wait()
		require.Contains(t, get(), "new")
		require.Equal(t, 3, fetches)
	})
}

func TestTransportRefreshesFetchedCatalog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		served := `{"old": {"repo": "tinfoilsh/old", "hosts": ["a.example"]}}`
		original := http.DefaultTransport
		defer func() { http.DefaultTransport = original }()
		http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, "https://gateway.example/catalog", req.URL.String())
			return newResponse(http.StatusOK, served), nil
		})
		tr, err := NewTransport(Config{BaseURL: "https://gateway.example/v1/", Relay: "gateway.example"})
		require.NoError(t, err)
		models := func() []string {
			models, err := tr.Models(context.Background())
			require.NoError(t, err)
			return models
		}
		require.Equal(t, []string{"old"}, models())
		served = `{"new": {"repo": "tinfoilsh/new", "hosts": ["b.example"]}}`
		time.Sleep(catalogRefreshInterval)
		require.Equal(t, []string{"old"}, models())
		synctest.Wait()
		require.Equal(t, []string{"new"}, models(), "the gateway's catalog is refreshed")
	})
}
