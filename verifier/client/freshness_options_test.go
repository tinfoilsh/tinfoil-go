package client

import (
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

func TestFreshnessExpirationUsesConfiguredAge(t *testing.T) {
	early := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	later := early.Add(time.Hour)
	for _, age := range []time.Duration{time.Hour, provenance.MaxFreshnessAge, 14 * 24 * time.Hour} {
		for _, pair := range [][2]time.Time{{early, later}, {later, early}, {early, early}} {
			deadline := freshnessExpiration(pair[0], pair[1], age)
			require.Equal(t, early.Add(age), deadline)
			require.Equal(t, deadline, freshnessExpiration(pair[0], pair[1], age), "unchanged witnesses keep their deadline")
		}
	}
}

func TestFreshnessOptionsArePerClient(t *testing.T) {
	first, err := NewSecureClientWithOptions("one.example", "org/repo", VerificationOptions{FreshnessMaxAge: time.Hour})
	require.NoError(t, err)
	second := NewSecureClient("two.example", "org/repo")
	first.setVerifiedState(&GroundTruth{EnclaveHost: "one.example"})
	require.NoError(t, first.SetFreshnessMaxAge(14*24*time.Hour))
	require.Nil(t, first.GroundTruth())
	require.Nil(t, first.VerificationDocument())
	require.Equal(t, "one.example", first.Enclave())
	require.Equal(t, 14*24*time.Hour, first.verificationOptions.freshnessMaxAge())
	require.Equal(t, 7*24*time.Hour, second.verificationOptions.freshnessMaxAge())
	for _, age := range []time.Duration{0, -time.Hour} {
		require.Error(t, first.SetFreshnessMaxAge(age))
	}
	require.Equal(t, 14*24*time.Hour, first.verificationOptions.freshnessMaxAge(), "invalid values cannot change policy")
	require.NoError(t, first.SetFreshnessMaxAgeSeconds(3600))
	require.Equal(t, time.Hour, first.verificationOptions.freshnessMaxAge())
	require.Error(t, first.SetFreshnessMaxAgeSeconds(math.MaxInt64))
	require.Error(t, first.SetFreshnessMaxAgeSeconds(0))
	_, err = NewSecureClientWithOptions("invalid.invalid", "org/repo", VerificationOptions{FreshnessMaxAge: -time.Hour})
	require.Error(t, err)
	_, err = VerifyDocumentV3WithOptions(nil, nil, "org/repo", VerificationOptions{FreshnessMaxAge: -time.Hour})
	require.ErrorContains(t, err, "freshness maximum age")
}

type freshnessRouterTransport struct{ response string }

func (r freshnessRouterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() == defaultRouterURL {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(r.response)), Request: req}, nil
	}
	return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unavailable")), Request: req}, nil
}

func TestDefaultRouterFallbackRetainsFreshnessPolicy(t *testing.T) {
	old := http.DefaultClient.Transport
	t.Cleanup(func() { http.DefaultClient.Transport = old })
	for _, routers := range []string{`[]`, `["router.example"]`, `not json`} {
		http.DefaultClient.Transport = freshnessRouterTransport{response: routers}
		c, err := NewDefaultClientWithOptions(VerificationOptions{FreshnessMaxAge: time.Hour})
		require.NoError(t, err)
		require.Equal(t, "inference.tinfoil.sh", c.Enclave())
		require.Equal(t, time.Hour, c.verificationOptions.freshnessMaxAge())
	}
}

func TestConcurrentFreshnessPolicyChanges(t *testing.T) {
	c := NewSecureClient("one.example", "org/repo")
	c.setVerifiedState(&GroundTruth{EnclaveHost: "one.example"})
	require.NotNil(t, c.GroundTruth())
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				_ = c.SetFreshnessMaxAge(time.Hour)
				c.GroundTruth()
			}
		})
	}
	wg.Wait()
	require.Nil(t, c.GroundTruth())
}
