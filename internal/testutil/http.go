package testutil

import (
	"fmt"
	"io"
	"net/http"
)

// Get fetches url and returns the body, failing on a non-2xx status. Live
// tests use it to pull real collateral; nothing in the SDK's own request path
// goes through it.
func Get(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP GET %s: %d %s", url, resp.StatusCode, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
