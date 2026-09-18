package client

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetExpectedRTMR3InvalidatesVerification(t *testing.T) {
	c := NewSecureClient("verified.example", "org/repo")
	c.setVerifiedState(&GroundTruth{EnclaveHost: "verified.example", TLSPublicKey: "key"})
	require.NotNil(t, c.GroundTruth())
	require.NotNil(t, c.VerificationDocument())
	c.SetExpectedRTMR3(strings.Repeat("ab", 48))
	require.Nil(t, c.GroundTruth())
	require.Nil(t, c.VerificationDocument())
	require.Equal(t, "verified.example", c.Enclave())
	require.Equal(t, "org/repo", c.Repo())
	require.Equal(t, strings.Repeat("ab", 48), c.verificationOptions.ExpectedRTMR3)
	c.SetExpectedRTMR3("")
	require.NoError(t, c.verificationOptions.validate())
}

func TestMalformedRTMR3RejectedBeforeDocumentFetch(t *testing.T) {
	c := NewSecureClient("invalid.invalid", "org/repo")
	c.SetExpectedRTMR3("sealed")
	_, err := c.VerifyV3()
	require.ErrorContains(t, err, "expected RTMR3")
	_, err = VerifyDocumentV3WithOptions(nil, nil, "org/repo", VerificationOptions{ExpectedRTMR3: "ab"})
	require.ErrorContains(t, err, "expected RTMR3")
}

func TestExpectedRTMR3ConcurrentStateAccess(t *testing.T) {
	c := NewSecureClient("verified.example", "org/repo")
	c.setVerifiedState(&GroundTruth{EnclaveHost: "verified.example"})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				c.SetExpectedRTMR3("")
				c.GroundTruth()
				c.VerificationDocument()
				c.Enclave()
			}
		})
	}
	wg.Wait()
	require.Nil(t, c.GroundTruth())
}

// Cached-state publication models the final, locked stage of VerifyV3. Invalid
// expectations make cache misses fail locally so the test needs no live service.
func TestHTTPClientConcurrentPolicyInvalidation(t *testing.T) {
	c := NewSecureClient("invalid.invalid", "org/repo")
	c.SetExpectedRTMR3("invalid")
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 500 {
			c.SetExpectedRTMR3("invalid")
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
			require.ErrorContains(t, err, "expected RTMR3")
		} else {
			require.NotNil(t, hc)
			require.Equal(t, "verified-key", hc.Transport.(*TLSBoundRoundTripper).ExpectedPublicKey)
		}
	}
	wg.Wait()
}
