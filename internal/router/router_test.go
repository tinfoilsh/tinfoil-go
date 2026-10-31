package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/internal/enclave"
	"github.com/tinfoilsh/tinfoil-go/internal/testutil"
	"github.com/tinfoilsh/tinfoil-go/internal/transport"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// newTLS is the transport Discover makes for each router in these tests.
var newTLS = transport.TLS

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
		s, err := Discover(context.Background(), nil, nil, newTLS)
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
	client, err := Discover(t.Context(), nil, nil, newTLS)
	require.NoError(t, err)
	assert.NotEmpty(t, client.Enclave().Host())
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
	defaultClient, err := enclave.New(enclave.Config{Host: "inference.tinfoil.sh", Repo: defaultRouterRepo})
	require.NoError(t, err)
	_, err = defaultClient.Verify()
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

func TestDiscoverBoundsTotalProbeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		original := http.DefaultClient
		defer func() { http.DefaultClient = original }()
		var routers []string
		for i := range 10 {
			routers = append(routers, fmt.Sprintf("router%d.example", i))
		}
		list, err := json.Marshal(routers)
		require.NoError(t, err)
		probes := make(map[string]int)
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == defaultRouterURL {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(list))}, nil
			}
			probes[req.URL.Host]++
			<-req.Context().Done() // an unreachable router
			return nil, req.Context().Err()
		})}
		start := time.Now()
		h, err := Discover(context.Background(), nil, nil, newTLS)
		require.NoError(t, err)
		require.Equal(t, "inference.tinfoil.sh", h.Enclave().Host(), "discovery falls back")
		require.Equal(t, discoveryTimeout, time.Since(start), "one budget for every probe, not one per router")
		synctest.Wait()
		require.Equal(t, map[string]int{"router0.example": 1}, probes, "no router is probed after the budget runs out")
	})
}
