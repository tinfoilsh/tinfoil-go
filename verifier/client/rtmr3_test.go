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
}
