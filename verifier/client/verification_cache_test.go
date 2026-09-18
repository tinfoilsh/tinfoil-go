package client

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// Cached-state publication models the final, locked stage of VerifyV3. An
// invalid URL makes cache misses fail locally, without contacting a service.
func TestHTTPClientConcurrentNonceCacheInvalidation(t *testing.T) {
	c := NewSecureClient("invalid\nhost", "org/repo")
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 500 {
			c.SetNoncedAttestation(true)
		}
	})
	wg.Go(func() {
		for range 500 {
			c.verifyMu.Lock()
			c.setVerifiedState(&GroundTruth{TLSPublicKey: "verified-key"})
			c.verifyMu.Unlock()
		}
	})
	for range 500 {
		hc, err := c.HTTPClient()
		if err != nil {
			require.ErrorContains(t, err, "invalid URL escape")
		} else {
			require.NotNil(t, hc)
			require.Equal(t, "verified-key", hc.Transport.(*TLSBoundRoundTripper).ExpectedPublicKey)
		}
	}
	wg.Wait()
}
