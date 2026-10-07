package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func TestConfigBoundRequiresIndependentTrustAndFreshness(t *testing.T) {
	policy := ConfigPolicy{Identity: "/org/project"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keys := []crypto.PublicKey{key.Public()}
	_, err = NewVerifier(WithFreshnessSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	_, err = NewVerifier(WithConfigSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	v, err := NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys([]crypto.PublicKey{key.Public()}), WithIgnoreFreshness())
	require.NoError(t, err)
	_, err = v.VerifyConfig(nil, nil, policy)
	require.ErrorContains(t, err, "requires config, platform, and runtime freshness")

	v, err = NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys([]crypto.PublicKey{key.Public()}))
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyConfig(raw, nonce, policy)
	require.ErrorContains(t, err, collateral.ConfigID)
	for name, bad := range map[string]ConfigPolicy{
		"identity": {Identity: "/org/project/extra"},
		"revision": {Identity: policy.Identity, Revision: "../v1"},
		"digest":   {Identity: policy.Identity, Digest: strings.Repeat("AB", 32)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyConfig(raw, nonce, bad)
			var e *ConfigurationError
			require.ErrorAs(t, err, &e)
		})
	}
}

func TestConfigBoundFreshnessExpirationIncludesEveryApproval(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Hour)
	for _, times := range [][3]time.Time{{older, now, now}, {now, older, now}, {now, now, older}} {
		require.Equal(t, older.Add(time.Hour), freshnessExpiration(time.Hour, times[0], times[1], times[2]))
	}
}
