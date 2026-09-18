package client

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetNoncedAttestationCompatibilityInvalidatesCache(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			c := NewSecureClient("verified.example", "org/repo")
			c.setVerifiedState(&GroundTruth{EnclaveHost: "verified.example", TLSPublicKey: "key"})
			require.NotNil(t, c.GroundTruth())
			require.NotNil(t, c.VerificationDocument())
			c.SetNoncedAttestation(enabled)
			require.Nil(t, c.GroundTruth())
			require.Nil(t, c.VerificationDocument())
			require.Equal(t, "verified.example", c.Enclave())
			require.Equal(t, "org/repo", c.Repo())
		})
	}
}
