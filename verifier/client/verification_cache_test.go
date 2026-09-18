package client

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Cached-state publication models the final, locked stage of VerifyV3. Invalid
// policy makes cache misses fail locally so the test needs no live service.
func TestHTTPClientConcurrentVerificationInvalidation(t *testing.T) {
	c := NewSecureClient("invalid.invalid", "org/repo")
	c.verificationOptions.FreshnessMaxAge = -time.Hour
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 500 {
			c.verifyMu.Lock()
			c.invalidateVerification()
			c.verifyMu.Unlock()
		}
	})
	wg.Go(func() {
		for range 500 {
			c.verifyMu.Lock()
			c.setVerifiedState(&GroundTruth{EnclaveHost: "invalid.invalid", TLSPublicKey: "verified-key"})
			c.verifyMu.Unlock()
		}
	})
	for range 500 {
		hc, err := c.HTTPClient()
		if err != nil {
			require.ErrorContains(t, err, "freshness maximum age")
		} else {
			require.NotNil(t, hc)
			require.Equal(t, "verified-key", hc.Transport.(*TLSBoundRoundTripper).ExpectedPublicKey)
		}
	}
	wg.Wait()
}
