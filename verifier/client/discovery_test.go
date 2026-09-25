package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRouterDiscoveryLimitsAndRedirects(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	for _, size := range []int{maxRouterResponseSize, maxRouterResponseSize + 1} {
		var redirects int
		http.DefaultClient = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { redirects++; return nil },
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/redirect" {
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"/redirect"}}, Body: http.NoBody}, nil
				}
				body := `[]` + strings.Repeat(" ", size-len(`[]`))
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
			}),
		}
		_, err := fetchRouters()
		require.Equal(t, 1, redirects)
		if size == maxRouterResponseSize {
			require.NoError(t, err)
		} else {
			require.ErrorContains(t, err, "exceeds")
		}
	}
}

func TestRouterDiscoveryUsesEarlierNetworkDeadline(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	for _, timeout := range []time.Duration{0, time.Second} {
		synctest.Test(t, func(t *testing.T) {
			http.DefaultClient = &http.Client{Timeout: timeout, Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, writer := io.Pipe()
				go func() { <-req.Context().Done(); writer.CloseWithError(req.Context().Err()) }()
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			})}
			start := time.Now()
			_, err := fetchRouters()
			require.ErrorIs(t, err, context.DeadlineExceeded)
			if timeout == 0 {
				timeout = routerFetchTimeout
			}
			require.Equal(t, timeout, time.Since(start))
		})
	}
}
