package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/document"
	"github.com/tinfoilsh/tinfoil-go/document/collateral"
)

func TestConfigBoundRequiresIndependentTrustAndFreshness(t *testing.T) {
	const ref = "org/project"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keys := []crypto.PublicKey{key.Public()}
	_, err = NewVerifier(WithFreshnessSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	_, err = NewVerifier(WithConfigSigningKeys(nil))
	require.ErrorContains(t, err, "must not be empty")
	v, err := NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys([]crypto.PublicKey{key.Public()}), WithIgnoreFreshness())
	require.NoError(t, err)
	_, err = v.VerifyConfig(nil, nil, ref)
	require.ErrorContains(t, err, "requires config, platform, and runtime freshness")

	v, err = NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys([]crypto.PublicKey{key.Public()}))
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyConfig(raw, nonce, ref)
	require.ErrorContains(t, err, collateral.ConfigID)
	for name, bad := range map[string]string{
		"identity": "org/project/extra",
		"revision": ref + "@../v1",
		"digest":   ref + "@sha256:" + strings.Repeat("AB", sha256.Size),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.VerifyConfig(raw, nonce, bad)
			var e *ConfigurationError
			require.ErrorAs(t, err, &e)
		})
	}
}

func TestParseConfigReference(t *testing.T) {
	const repo = "org/project"
	digest := strings.Repeat("ab", sha256.Size)
	for _, pins := range [][2]string{{}, {"v1", ""}, {"", digest}, {"v1", digest}} {
		ref := repo
		if pins[0] != "" {
			ref += "@" + pins[0]
		}
		if pins[1] != "" {
			ref += "@sha256:" + pins[1]
		}
		identity, revision, hash, err := ParseConfigReference(ref)
		require.NoError(t, err)
		require.Equal(t, "/"+repo, identity)
		require.Equal(t, pins[0], revision)
		require.Equal(t, pins[1], hash)
	}
	for _, ref := range []string{"", "/org/project", "Org/project", "org/project_name", "org/project@v1/path", "org/project@sha256:bad", "org/project@v1@v2"} {
		_, _, _, err := ParseConfigReference(ref)
		require.Error(t, err, ref)
	}
}

func TestConfigBoundFreshnessExpirationIncludesEveryApproval(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Hour)
	for _, times := range [][3]time.Time{{older, now, now}, {now, older, now}, {now, now, older}} {
		require.Equal(t, older.Add(time.Hour), freshnessExpiration(time.Hour, times[0], times[1], times[2]))
	}
}
