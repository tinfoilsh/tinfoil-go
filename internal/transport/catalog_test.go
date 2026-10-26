package transport

import (
	"strings"
	"testing"

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
