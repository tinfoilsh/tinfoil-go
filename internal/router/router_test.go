package router

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDefaultClientProbesOncePerDiscovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cause := errors.New("unavailable")
		requests := make(map[string]int)
		original := http.DefaultClient
		defer func() { http.DefaultClient = original }()
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests[req.URL.Host]++
			if req.URL.String() == defaultRouterURL {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`["router.example"]`))}, nil
			}
			return nil, cause
		})}
		s, err := Discover(context.Background(), nil)
		if err == nil {
			// Complete initialization if the constructor returned a lazy fallback.
			_, err = s.Reverify(context.Background())
		}
		require.ErrorIs(t, err, cause)
		require.Positive(t, requests["atc.tinfoil.sh"])
		require.Equal(t, requests["atc.tinfoil.sh"], requests["router.example"], "one candidate probe per discovery")
		require.Equal(t, 2, requests["inference.tinfoil.sh"], "fallback verification has one retry")
	})
}

func TestLiveDiscoverRouter(t *testing.T) {
	testutil.RequireLive(t)
	client, err := Discover(t.Context(), nil)
	require.NoError(t, err)
	assert.NotEmpty(t, client.Enclave())
	_, err = client.Reverify(t.Context())
	assert.NoError(t, err)
}

func TestLiveClientFetchRouters(t *testing.T) {
	testutil.RequireLive(t)
	routers, err := fetchRouters(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, routers)
	assert.True(t, strings.HasSuffix(routers[0], ".tinfoil.sh"))
}

func TestLiveClientFallbackEnclave(t *testing.T) {
	testutil.RequireLive(t)
	defaultClient, err := enclave.NewHandle(enclave.Config{Host: "inference.tinfoil.sh", Repo: defaultRouterRepo})
	require.NoError(t, err)
	_, err = defaultClient.Reverify(t.Context())
	assert.NoError(t, err)
}

func TestFetchRoutersRefusesInsecureRedirects(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	for _, tc := range []struct {
		location string
		refused  bool
	}{
		{"https://mirror.example/routers", false},
		{"http://mirror.example/routers", true},
	} {
		t.Run(tc.location, func(t *testing.T) {
			http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == defaultRouterURL {
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {tc.location}}, Body: http.NoBody}, nil
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`["router.example"]`))}, nil
			})}
			routers, err := fetchRouters(context.Background())
			if tc.refused {
				require.ErrorContains(t, err, "refusing redirect to non-HTTPS URL")
				return
			}
			require.NoError(t, err)
			require.Equal(t, []string{"router.example"}, routers)
		})
	}
}
