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
	"github.com/tinfoilsh/tinfoil-go/tinfoil-config/endorsement"
)

func TestIGVMRequiresIndependentTrustAndFreshness(t *testing.T) {
	policy := ConfigPolicy{Identity: "/org/project", AuditScope: "16a44d18-3387-44ce-9bfb-d77c4d27dbba"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keys := []endorsement.SigningKey{{PublicKey: key.Public(), AuditScope: policy.AuditScope}}
	v, err := NewVerifier()
	require.NoError(t, err)
	_, err = v.VerifyIGVM(nil, nil, policy)
	require.ErrorContains(t, err, "pinned signing keys")
	v, err = NewVerifier(WithConfigSigningKeys(keys))
	require.NoError(t, err)
	_, err = v.VerifyIGVM(nil, nil, policy)
	require.ErrorContains(t, err, "signing keys for configs and freshness")
	_, err = NewVerifier(WithFreshnessSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	_, err = NewVerifier(WithConfigSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	v, err = NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys([]crypto.PublicKey{key.Public()}), WithIgnoreFreshness())
	require.NoError(t, err)
	_, err = v.VerifyIGVM(nil, nil, policy)
	require.ErrorContains(t, err, "requires config, platform, and runtime freshness")

	v, err = NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys([]crypto.PublicKey{key.Public()}))
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyIGVM(raw, nonce, policy)
	require.ErrorContains(t, err, collateral.ConfigID)
	for name, bad := range map[string]ConfigPolicy{
		"identity": {Identity: "/org/project/extra", AuditScope: policy.AuditScope},
		"scope":    {Identity: policy.Identity, AuditScope: "untrusted"},
		"revision": {Identity: policy.Identity, AuditScope: policy.AuditScope, Revision: "../v1"},
		"digest":   {Identity: policy.Identity, AuditScope: policy.AuditScope, Digest: strings.Repeat("AB", 32)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyIGVM(raw, nonce, bad)
			var e *ConfigurationError
			require.ErrorAs(t, err, &e)
		})
	}
}

func TestIGVMFreshnessExpirationIncludesEveryApproval(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Hour)
	for _, times := range [][3]time.Time{{older, now, now}, {now, older, now}, {now, now, older}} {
		require.Equal(t, older.Add(time.Hour), freshnessExpiration(time.Hour, times[0], times[1], times[2]))
	}
}
