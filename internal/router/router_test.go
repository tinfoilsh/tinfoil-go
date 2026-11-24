package router

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
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
		s, err := Discover(context.Background(), Options{NewTransport: newTLS})
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
	client, err := Discover(t.Context(), Options{NewTransport: newTLS})
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
	defaultClient, err := enclave.New(enclave.Config{Host: "inference.tinfoil.sh", Pin: defaultRouterPin})
	require.NoError(t, err)
	_, err = defaultClient.Verify(nil)
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
	keepOrder(t)
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
		h, err := Discover(context.Background(), Options{NewTransport: newTLS})
		require.NoError(t, err)
		require.Equal(t, "inference.tinfoil.sh", h.Enclave().Host(), "discovery falls back")
		require.Equal(t, discoveryTimeout, time.Since(start), "one budget for every probe, not one per router")
		synctest.Wait()
		require.Equal(t, map[string]int{"router0.example": 1}, probes, "no router is probed after the budget runs out")
	})
}

func TestRelayListURL(t *testing.T) {
	for relay, want := range map[string]string{
		"https://app.example":           "https://app.example/routers",
		"https://app.example/":          "https://app.example/routers",
		"https://app.example/tinfoil":   "https://app.example/tinfoil/routers",
		"https://app.example/tinfoil/":  "https://app.example/tinfoil/routers",
		"http://127.0.0.1:8080/tinfoil": "http://127.0.0.1:8080/tinfoil/routers",
	} {
		got, err := RelayListURL(relay)
		require.NoError(t, err, relay)
		require.Equal(t, want, got, relay)
	}
	for _, bad := range []string{"", "/tinfoil", "https://app.example/?", "https://app.example#x", "https://u:p@app.example"} {
		_, err := RelayListURL(bad)
		require.Error(t, err, bad)
	}
}

// A caller's list goes through discovery as Tinfoil's does: each router is
// tried once, under the same attestation fetcher as the fallback, and a list
// that can't be obtained counts as empty.
func TestDiscoverUsesTheCallersListAndFetcher(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Errorf("nothing is fetched directly, but %s was", req.URL)
		return nil, errors.New("no network in this test")
	})}
	for name, tc := range map[string]struct {
		list ListFunc
		want []string
	}{
		"list":       {func(context.Context) ([]string, error) { return []string{"a.example", "b.example"}, nil }, []string{"a.example", "b.example", "inference.tinfoil.sh"}},
		"empty list": {func(context.Context) ([]string, error) { return nil, nil }, []string{"inference.tinfoil.sh"}},
		"list error": {func(context.Context) ([]string, error) { return []string{"a.example"}, errors.New("unavailable") }, []string{"inference.tinfoil.sh"}},
	} {
		t.Run(name, func(t *testing.T) {
			keepOrder(t)
			synctest.Test(t, func(t *testing.T) {
				var hosts []string
				fetchDocument := func(_ context.Context, host string, _ []byte) ([]byte, error) {
					hosts = append(hosts, host)
					return nil, errors.New("unreachable")
				}
				s, err := Discover(context.Background(), Options{NewTransport: newTLS, List: tc.list, FetchAttestation: fetchDocument})
				require.NoError(t, err)
				require.Equal(t, "inference.tinfoil.sh", s.Enclave().Host())
				_, err = s.Reverify(context.Background())
				require.Error(t, err)
				require.Equal(t, tc.want, hosts[:len(hosts)-1], "every router is tried once, then the fallback")
				require.Equal(t, "inference.tinfoil.sh", hosts[len(hosts)-1], "the fallback is verified with a retry")
			})
		})
	}
}

func TestFetchListAppliesTheListRules(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	for body, ok := range map[string]bool{
		`["a.example","b.example"]`: true,
		`{"routers":["a.example"]}`: false,
		`[1]`:                       false,
		"[\"" + strings.Repeat("a", maxRouterBytes) + "\"]": false,
	} {
		http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			require.Equal(t, "https://app.example/tinfoil/routers", req.URL.String())
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		routers, err := FetchList(t.Context(), "https://app.example/tinfoil/routers")
		if ok {
			require.NoError(t, err)
			require.Equal(t, []string{"a.example", "b.example"}, routers)
		} else {
			require.Error(t, err, "%.40s", body)
		}
	}
}

// keepOrder makes Discover try routers in the order that the list gives them,
// for the duration of t.
func keepOrder(t *testing.T) {
	original := shuffle
	t.Cleanup(func() { shuffle = original })
	shuffle = func([]string) {}
}

func TestDiscoverShufflesACopyOfTheList(t *testing.T) {
	list := []string{"a.example", "b.example", "c.example"}
	original := shuffle
	t.Cleanup(func() { shuffle = original })
	shuffle = slices.Reverse[[]string]
	synctest.Test(t, func(t *testing.T) {
		var hosts []string
		fetchDocument := func(_ context.Context, host string, _ []byte) ([]byte, error) {
			hosts = append(hosts, host)
			return nil, errors.New("unreachable")
		}
		_, err := Discover(context.Background(), Options{NewTransport: newTLS, List: func(context.Context) ([]string, error) { return list, nil }, FetchAttestation: fetchDocument})
		require.NoError(t, err)
		require.Equal(t, []string{"c.example", "b.example", "a.example"}, hosts[:3], "routers are tried in the shuffled order")
		require.Equal(t, []string{"a.example", "b.example", "c.example"}, list, "the caller's slice is left alone")
	})
}

func TestShuffleVariesTheFirstRouter(t *testing.T) {
	first := map[string]bool{}
	for range 100 {
		routers := []string{"a.example", "b.example", "c.example", "d.example"}
		shuffle(routers)
		require.ElementsMatch(t, []string{"a.example", "b.example", "c.example", "d.example"}, routers)
		first[routers[0]] = true
	}
	require.Greater(t, len(first), 1, "a uniform shuffle doesn't always put the same router first")
}
