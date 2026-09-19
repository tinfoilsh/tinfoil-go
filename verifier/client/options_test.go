package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/provenance"
)

func TestVerificationOptions(t *testing.T) {
	for _, age := range []time.Duration{0, time.Hour, 14 * 24 * time.Hour} {
		options := VerificationOptions{FreshnessMaxAge: age}
		client, err := NewSecureClientWithOptions("enclave.example", "org/repo", options)
		require.NoError(t, err)
		want := age
		if want == 0 {
			want = provenance.MaxFreshnessAge
		}
		options.FreshnessMaxAge = time.Nanosecond
		require.Equal(t, want, client.freshnessMaxAge, "client policy must be copied")
		require.Equal(t, "enclave.example", client.Enclave())
		require.Equal(t, "org/repo", client.Repo())
	}
	require.Equal(t, provenance.MaxFreshnessAge, NewSecureClient("enclave.example", "org/repo").freshnessMaxAge)
}

func TestInvalidFreshnessAgeFailsBeforeVerification(t *testing.T) {
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid options must fail before any network request")
		return nil, errors.New("unexpected request")
	})}
	options := VerificationOptions{FreshnessMaxAge: -time.Second}
	_, err := NewSecureClientWithOptions("enclave.example", "org/repo", options)
	require.ErrorContains(t, err, "freshness max age")
	_, err = NewDefaultClientWithOptions(options)
	require.ErrorContains(t, err, "freshness max age")
	_, err = VerifyDocumentV3WithOptions(nil, nil, "org/repo", options)
	require.ErrorContains(t, err, "freshness max age")
}

func TestRouterFallbackRetainsFreshnessPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, routers string
		wantTried     []string
	}{
		{"discovery unavailable", "unavailable", nil},
		{"no routers", "[]", nil},
		{"all routers fail", `["first.example","second.example"]`, []string{"first.example", "second.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := http.DefaultClient
			t.Cleanup(func() { http.DefaultClient = original })
			var tried []string
			http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != defaultRouterURL {
					tried = append(tried, req.URL.Host)
					return nil, errors.New("router unavailable")
				}
				if tc.routers == "unavailable" {
					return nil, errors.New("router discovery unavailable")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.routers))}, nil
			})}
			client, err := NewDefaultClientWithOptions(VerificationOptions{FreshnessMaxAge: time.Hour})
			require.NoError(t, err)
			require.Equal(t, "inference.tinfoil.sh", client.Enclave())
			require.Equal(t, time.Hour, client.freshnessMaxAge)
			require.Equal(t, tc.wantTried, tried)
		})
	}
}
