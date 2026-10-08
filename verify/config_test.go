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
	v, err := NewVerifier(WithConfigSigningKeys(keys), WithFreshnessSigningKeys(keys), WithIgnoreFreshness())
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	_, err = v.VerifyV3(raw, nonce, ref)
	require.ErrorContains(t, err, "requires config, platform, and runtime freshness")
}

func TestCollateralVersionSelectsVerification(t *testing.T) {
	v, err := NewVerifier()
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	for _, tc := range []struct{ format, want string }{
		{"", collateral.SigstoreCodeV1Format},
		{collateral.FormatV2, collateral.SigstoreCodeV1Format},
		{collateral.FormatV3, collateral.ConfigID},
	} {
		t.Run(tc.format, func(t *testing.T) {
			raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: tc.format}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
			require.NoError(t, err)
			_, rejectedAt, err := v.verifyV3(raw, nonce, "org/project")
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, layerProvenance, rejectedAt)
		})
	}
}

func TestConfigReferencePins(t *testing.T) {
	v, err := NewVerifier()
	require.NoError(t, err)
	nonce := make([]byte, document.NonceSize)
	raw, err := document.Build(document.BuildInput{Nonce: nonce, CollateralFormat: collateral.FormatV3}, func([64]byte) (string, []byte, error) { return document.SEVSNPReportV1Format, []byte("quote"), nil })
	require.NoError(t, err)
	const repo = "org/project"
	digest := strings.Repeat("ab", sha256.Size)
	for _, ref := range []string{repo, repo + "@v1", repo + "@sha256:" + digest, repo + "@v1@sha256:" + digest} {
		_, err := v.VerifyV3(raw, nonce, ref)
		require.ErrorIs(t, err, collateral.ErrNotFound, "valid pins must reach endorsement verification")
	}
	for _, ref := range []string{"", "/org/project", "Org/project", "org/project_name", "org/project@v1/path", "org/project@sha256:bad", "org/project@v1@v2"} {
		_, err := v.VerifyV3(raw, nonce, ref)
		var configErr *ConfigurationError
		require.ErrorAs(t, err, &configErr, ref)
	}
}

func TestConfigBoundFreshnessExpirationIncludesEveryApproval(t *testing.T) {
	now := time.Now()
	older := now.Add(-time.Hour)
	for _, times := range [][3]time.Time{{older, now, now}, {now, older, now}, {now, now, older}} {
		require.Equal(t, older.Add(time.Hour), freshnessExpiration(time.Hour, times[0], times[1], times[2]))
	}
}
