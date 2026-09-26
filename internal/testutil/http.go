package testutil

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// fetchTimeout bounds each live-test fetch so a stalled collateral service
// fails that test rather than holding the suite until its global timeout.
const fetchTimeout = 30 * time.Second

var fetchClient = &http.Client{Timeout: fetchTimeout}

// Get fetches url and returns the body, failing on a non-2xx status. Live
// tests use it to pull real collateral; nothing in the SDK's own request path
// goes through it.
func Get(url string) ([]byte, error) {
	resp, err := fetchClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP GET %s: %d %s", url, resp.StatusCode, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
