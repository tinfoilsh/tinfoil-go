package tinfoil

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

func TestGatewayVerifications(t *testing.T) {
	var catalog atomic.Pointer[Catalog]
	catalog.Store(&Catalog{sealTestModel: {Repo: "tinfoilsh/test", Hosts: []string{sealTestInitial}}})
	g, err := NewGateway("https://gateway.example", func() Catalog { return *catalog.Load() }, GatewayOptions{})
	require.NoError(t, err)
	require.Empty(t, g.Verifications(), "catalog entries are not verification results")

	var latest atomic.Pointer[client.VerifiedDocumentV3]
	g.seal.build = func(r replica) (http.RoundTripper, error) {
		return &verifiedReplicaTransport{
			recoveryTransport: &recoveryTransport{transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return newResponse(http.StatusNoContent, ""), nil
			})},
			verification: func() *client.VerifiedDocumentV3 { return latest.Load() },
		}, nil
	}
	send := func() {
		req, _ := http.NewRequest(http.MethodGet, "https://gateway.example/test", nil)
		req.Header.Set(modelHeader, sealTestModel)
		resp, err := g.HTTPClient().Do(req)
		require.NoError(t, err)
		resp.Body.Close()
	}
	send()
	require.Empty(t, g.Verifications(), "a missing verification is never reported as successful")
	latest.Store(&client.VerifiedDocumentV3{EnclaveHost: sealTestInitial, CodeDigest: "first"})
	results := g.Verifications()
	require.Len(t, results, 1)
	require.Equal(t, []string{sealTestModel}, results[0].Models)
	require.Equal(t, "tinfoilsh/test", results[0].Reference)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				send()
				require.Len(t, g.Verifications(), 1)
			}
		})
	}
	wg.Wait()
	latest.Store(&client.VerifiedDocumentV3{EnclaveHost: sealTestInitial, CodeDigest: "refreshed", FreshnessExpiresAt: time.Now().Add(-time.Minute)})
	catalog.Store(&Catalog{})
	results = g.Verifications()
	require.Len(t, results, 1, "catalog removal and expiry do not erase historical evidence")
	require.Equal(t, "refreshed", results[0].Verification.CodeDigest, "read the current result, not a construction-time copy")
	results[0].Models[0] = "mutated"
	require.Equal(t, []string{sealTestModel}, g.Verifications()[0].Models)
}
