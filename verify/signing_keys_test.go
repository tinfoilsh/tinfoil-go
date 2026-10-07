package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify/internal/endorsement"
)

func TestPublicConfigTrustAndPrivateOverride(t *testing.T) {
	var registry struct {
		Config []byte          `json:"config"`
		Bundle json.RawMessage `json:"bundle"`
	}
	require.NoError(t, json.Unmarshal(capturedFixture(t, "registry", "canary-endorsement.json"), &registry))
	policy := endorsement.ConfigPolicy{Identity: "/tinfoil/registry-canary", IgnoreFreshness: true}
	public, err := NewVerifier()
	require.NoError(t, err)
	verified, err := public.configVerifier.Verify(registry.Config, registry.Bundle, policy)
	require.NoError(t, err)
	const productionKeyHint = "J4/dwixneOvUPEEizF3WGcRiLOpQvzk5Kd8ThACLK60="
	require.Equal(t, productionKeyHint, verified.SigningKeyHint)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	private, err := NewVerifier(WithConfigSigningKeys([]crypto.PublicKey{key.Public()}))
	require.NoError(t, err)
	_, err = private.configVerifier.Verify(registry.Config, registry.Bundle, policy)
	require.ErrorContains(t, err, "untrusted approval signing key")
}
