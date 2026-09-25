package document

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

type fetchTransport func(*http.Request) (*http.Response, error)

func (f fetchTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchSizeLimitAndRedirects(t *testing.T) {
	const limit = 32 << 20
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	for _, size := range []int{limit, limit + 1} {
		redirects := 0
		http.DefaultClient = &http.Client{
			Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/redirect" {
					redirects++
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"/redirect"}}, Body: http.NoBody}, nil
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", size)))}, nil
			}),
		}
		body, err := Fetch("enclave.example", testNonce())
		require.Equal(t, 1, redirects)
		if size > limit {
			require.ErrorContains(t, err, "exceeds 33554432 bytes")
			require.Nil(t, body)
		} else {
			require.NoError(t, err)
			require.Len(t, body, size)
		}
	}
}

func TestFetchTimeout(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	for _, timeout := range []time.Duration{0, time.Second} {
		synctest.Test(t, func(t *testing.T) {
			http.DefaultClient = &http.Client{Timeout: timeout, Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
				body, writer := io.Pipe()
				go func() {
					<-r.Context().Done()
					writer.CloseWithError(r.Context().Err())
				}()
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			})}
			start := time.Now()
			_, err := Fetch("enclave.example", testNonce())
			require.ErrorIs(t, err, context.DeadlineExceeded)
			if timeout == 0 {
				timeout = 30 * time.Second
			}
			require.Equal(t, timeout, time.Since(start))
		})
	}
}

func TestFetchRejectsNonHTTPSRedirect(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	var schemes []string
	http.DefaultClient = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
		Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
			schemes = append(schemes, r.URL.Scheme)
			if r.URL.Scheme != "https" {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("plaintext document"))}, nil
			}
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"http://enclave.example/redirect"}}, Body: http.NoBody}, nil
		}),
	}
	_, err := Fetch("enclave.example", testNonce())
	require.ErrorContains(t, err, "refusing redirect to non-HTTPS URL")
	require.Equal(t, []string{"https"}, schemes)
}

func TestFetchKeepsDefaultRedirectLimit(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	requests := 0
	http.DefaultClient = &http.Client{Transport: fetchTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"/loop"}}, Body: http.NoBody}, nil
	})}
	_, err := Fetch("enclave.example", testNonce())
	require.ErrorContains(t, err, "stopped after 10 redirects")
	require.Equal(t, 10, requests)
}
